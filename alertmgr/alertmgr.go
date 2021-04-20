package alertmgr

import (
	"fmt"
	"github.com/aquasecurity/postee/eventservice"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aquasecurity/postee/dbservice"
	"github.com/aquasecurity/postee/plugins"
	"github.com/aquasecurity/postee/scanservice"
	"github.com/aquasecurity/postee/utils"
	"github.com/ghodss/yaml"
)

const (
	IssueTypeDefault = "Task"
	PriorityDefault  = "High"

	ServiceNowTableDefault = "incident"
	AnonymizeReplacement   = "<hidden>"
)

type PluginSettings struct {
	Name            string   `json:"name"`
	Type            string   `json:"type"`
	Enable          bool     `json:"enable"`
	Url             string   `json:"url"`
	User            string   `json:"user"`
	Password        string   `json:"password"`
	TlsVerify       bool     `json:"tls_verify"`
	ProjectKey      string   `json:"project_key,omitempty" structs:"project_key,omitempty"`
	IssueType       string   `json:"issuetype" structs:"issuetype"`
	BoardName       string   `json:"board,omitempty" structs:"board,omitempty"`
	Priority        string   `json:"priority,omitempty"`
	Assignee        []string `json:"assignee,omitempty"`
	Description     string
	Summary         string            `json:"summary,omitempty"`
	FixVersions     []string          `json:"fixVersions,omitempty"`
	AffectsVersions []string          `json:"affectsVersions,omitempty"`
	Labels          []string          `json:"labels,omitempty"`
	Sprint          string            `json:"sprint,omitempty"`
	Unknowns        map[string]string `json:"unknowns" structs:"unknowns,omitempty"`

	Host       string   `json:"host"`
	Port       string   `json:"port"`
	Recipients []string `json:"recipients"`
	Sender     string   `json:"sender"`
	Token      string   `json:"token"`
	UseMX      bool     `json:"useMX"`

	PolicyMinVulnerability string   `json:"Policy-Min-Vulnerability"`
	PolicyRegistry         []string `json:"Policy-Registry"`
	PolicyImageName        []string `json:"Policy-Image-Name"`
	PolicyNonCompliant     bool     `json:"Policy-Non-Compliant"`
	PolicyShowAll          bool     `json:"Policy-Show-All"`

	IgnoreRegistry  []string `json:"Ignore-Registry"`
	IgnoreImageName []string `json:"Ignore-Image-Name"`

	AggregateIssuesNumber  int    `json:"Aggregate-Issues-Number"`
	AggregateIssuesTimeout string `json:"Aggregate-Issues-Timeout"`
	InstanceName           string `json:"instance"`
	PolicyOnlyFixAvailable bool   `json:"Policy-Only-Fix-Available"`

	PolicyOPA []string `json:"Policy-OPA"`

	AquaServer      string `json:"AquaServer"`
	DBMaxSize       int    `json:"Max_DB_Size"`
	DBRemoveOldData int    `json:"Delete_Old_Data"`
	DBTestInterval  int    `json:"DbVerifyInterval"`

	SizeLimit int `json:"SizeLimit"`
}

type AlertMgr struct {
	mutexScan  sync.Mutex
	mutexEvent sync.Mutex
	quit       chan struct{}
	queue      chan string
	events     chan string
	cfgFiles   []string
	plugins    map[string]plugins.Plugin
}

var initCtx sync.Once
var alertmgrCtx *AlertMgr
var aquaServer string
var baseForTicker = time.Hour
var ticker *time.Ticker

var osStat = os.Stat

func Instance() *AlertMgr {
	initCtx.Do(func() {
		alertmgrCtx = &AlertMgr{
			mutexScan:  sync.Mutex{},
			mutexEvent: sync.Mutex{},
			quit:       make(chan struct{}),
			events:     make(chan string, 1000),
			queue:      make(chan string, 1000),
			plugins:    make(map[string]plugins.Plugin),
		}
	})
	return alertmgrCtx
}

func (ctx *AlertMgr) Start(files []string) {
	log.Printf("Starting AlertMgr....")
	ctx.cfgFiles = files
	if err := ctx.load(); err != nil {
		log.Printf("load() error: %v", err)
		return
	}
	go ctx.listen()
}

func (ctx *AlertMgr) Terminate() {
	log.Printf("Terminating AlertMgr....")
	close(ctx.quit)
	for _, plugin := range ctx.plugins {
		if plugin != nil {
			plugin.Terminate()
		}
	}
	if ticker != nil {
		ticker.Stop()
	}
}

func (ctx *AlertMgr) Event(data string) {
	ctx.mutexEvent.Lock()
	defer ctx.mutexEvent.Unlock()
	ctx.events <- data
}

func (ctx *AlertMgr) Send(data string) {
	ctx.mutexScan.Lock()
	defer ctx.mutexScan.Unlock()
	ctx.queue <- data
}

func (ctx *AlertMgr) load() error {
	for _, file := range ctx.cfgFiles {
		if err := ctx.loadFile(file); err != nil {
			return err
		}
	}
	return nil
}

func (ctx *AlertMgr) loadFile(cfgFile string) error {
	ctx.mutexScan.Lock()
	defer ctx.mutexScan.Unlock()
	log.Printf("Loading alerts configuration file %s ....\n", cfgFile)
	data, err := ioutil.ReadFile(cfgFile)
	if err != nil {
		log.Printf("Failed to open file %s, %s", cfgFile, err)
		return err
	}
	pluginSettings := []PluginSettings{}
	err = yaml.Unmarshal(data, &pluginSettings)
	if err != nil {
		log.Printf("Failed yaml.Unmarshal, %s", err)
		return err
	}
	for name, plugin := range ctx.plugins {
		if plugin != nil {
			ctx.plugins[name] = nil
			plugin.Terminate()
		}
	}

	ignoreAuthorization := map[string]bool{
		"slack":   true,
		"teams":   true,
		"webhook": true,
		"email":   true,
		"splunk":  true,
	}

	for _, settings := range pluginSettings {
		utils.Debug("%#v\n", anonymizeSettings(&settings))
		if settings.Type == "common" {
			if len(settings.AquaServer) > 0 {
				var slash string
				if !strings.HasSuffix(settings.AquaServer, "/") {
					slash = "/"
				}
				aquaServer = fmt.Sprintf("%s%s#/images/", settings.AquaServer, slash)
			}
			dbservice.DbSizeLimit = settings.DBMaxSize
			dbservice.DbDueDate = settings.DBRemoveOldData

			if settings.DBTestInterval == 0 {
				settings.DBTestInterval = 1
			}

			if dbservice.DbSizeLimit != 0 || dbservice.DbDueDate != 0 {
				ticker = time.NewTicker(baseForTicker * time.Duration(settings.DBTestInterval))
				go func() {
					for range ticker.C {
						dbservice.CheckSizeLimit()
						dbservice.CheckExpiredData()
					}
				}()
			}
			continue
		}

		if settings.Enable {
			settings.User = utils.GetEnvironmentVarOrPlain(settings.User)
			if len(settings.User) == 0 && !ignoreAuthorization[settings.Type] {
				log.Printf("User for %q is empty", settings.Name)
				continue
			}
			settings.Password = utils.GetEnvironmentVarOrPlain(settings.Password)
			if len(settings.Password) == 0 && !ignoreAuthorization[settings.Type] {
				log.Printf("Password for %q is empty", settings.Name)
				continue
			}
			utils.Debug("Starting Plugin %q: %q\n", settings.Type, settings.Name)
			switch settings.Type {
			case "jira":
				ctx.plugins[settings.Name] = buildJiraPlugin(&settings)
			case "email":
				ctx.plugins[settings.Name] = buildEmailPlugin(&settings)
			case "slack":
				ctx.plugins[settings.Name] = buildSlackPlugin(&settings)
			case "teams":
				ctx.plugins[settings.Name] = buildTeamsPlugin(&settings)
			case "serviceNow":
				ctx.plugins[settings.Name] = buildServiceNow(&settings)
			case "webhook":
				ctx.plugins[settings.Name] = buildWebhookPlugin(&settings)
			case "splunk":
				ctx.plugins[settings.Name] = buildSplunkPlugin(&settings)
			default:
				log.Printf("Plugin type %q is undefined or empty. Plugin name is %q.",
					settings.Type, settings.Name)
				continue
			}
			ctx.plugins[settings.Name].Init()
		}
	}
	return nil
}

type service interface {
	ResultHandling(input string, plugins map[string]plugins.Plugin)
}

var getScanService = func() service {
	serv := &scanservice.ScanService{}
	return serv
}
var getEventService = func() service {
	serv := &eventservice.EventService{}
	return serv
}

func (ctx *AlertMgr) listen() {
	for {
		select {
		case <-ctx.quit:
			return
		case data := <-ctx.queue:
			go getScanService().ResultHandling(strings.ReplaceAll(data, "`", "'"), ctx.plugins)
		case event := <-ctx.events:
			go getEventService().ResultHandling(event, ctx.plugins)
		}
	}
}
