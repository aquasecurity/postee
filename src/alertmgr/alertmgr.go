package alertmgr

import (
	"dbservice"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"plugins"
	"scanservice"
	"settings"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghodss/yaml"
	"utils"
)

const (
	IssueTypeDefault = "Task"
	PriorityDefault  = "High"

	ServiceNowTableDefault = "incident"
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
	mutex   sync.Mutex
	quit    chan struct{}
	queue   chan string
	cfgfile string
	plugins map[string]plugins.Plugin
}

var initCtx sync.Once
var alertmgrCtx *AlertMgr
var aquaServer string
var baseForTicker = time.Hour
var ticker *time.Ticker

var osStat = os.Stat

func buildSettings(sourceSettings *PluginSettings) *settings.Settings {
	var timeout int
	var err error

	times := map[string]int{
		"s": 1,
		"m": 60,
		"h": 3600,
	}

	if len(sourceSettings.AggregateIssuesTimeout) > 0 {
		wasConvert := false
		for suffix, k := range times {
			if strings.HasSuffix(strings.ToLower(sourceSettings.AggregateIssuesTimeout), suffix) {
				timeout, err = strconv.Atoi(strings.TrimSuffix(sourceSettings.AggregateIssuesTimeout, suffix))
				timeout *= k
				wasConvert = true
				break
			}
		}
		if !wasConvert {
			timeout, err = strconv.Atoi(sourceSettings.AggregateIssuesTimeout)
		}
		if err != nil {
			log.Printf("%q settings: Can't convert 'AggregateIssuesTimeout'(%q) to seconds.",
				sourceSettings.Name, sourceSettings.AggregateIssuesTimeout)
		}
	}
	opaPolicy := []string{}
	if len(sourceSettings.PolicyOPA) > 0 {
		for _, policyFile := range sourceSettings.PolicyOPA {
			if _, err := osStat(policyFile); err != nil {
				if os.IsNotExist(err) {
					log.Printf("Policy file %q doesn't exist.", policyFile)
				} else {
					log.Printf("There is a problem with %q polycy: %v", policyFile, err)
				}
				continue
			}
			opaPolicy = append(opaPolicy, policyFile)
		}
	}

	return &settings.Settings{
		PluginName:              sourceSettings.Name,
		PolicyMinVulnerability:  sourceSettings.PolicyMinVulnerability,
		PolicyRegistry:          sourceSettings.PolicyRegistry,
		PolicyImageName:         sourceSettings.PolicyImageName,
		PolicyShowAll:           sourceSettings.PolicyShowAll,
		PolicyNonCompliant:      sourceSettings.PolicyNonCompliant,
		IgnoreRegistry:          sourceSettings.IgnoreRegistry,
		IgnoreImageName:         sourceSettings.IgnoreImageName,
		AggregateIssuesNumber:   sourceSettings.AggregateIssuesNumber,
		AggregateTimeoutSeconds: timeout,
		PolicyOnlyFixAvailable:  sourceSettings.PolicyOnlyFixAvailable,
		AquaServer:              aquaServer,
		PolicyOPA:               opaPolicy,
	}
}

func buildSplunkPlugin(sourceSettings *PluginSettings) *plugins.SplunkPlugin {
	return &plugins.SplunkPlugin{
		Url:            sourceSettings.Url,
		Token:          sourceSettings.Token,
		SplunkSettings: buildSettings(sourceSettings),
		EventLimit:     sourceSettings.SizeLimit,
	}
}

func buildWebhookPlugin(sourceSettings *PluginSettings) *plugins.WebhookPlugin {
	return &plugins.WebhookPlugin{
		Url:             sourceSettings.Url,
		WebhookSettings: buildSettings(sourceSettings),
	}
}

func buildTeamsPlugin(sourceSettings *PluginSettings) *plugins.TeamsPlugin {
	teams := &plugins.TeamsPlugin{
		Webhook: sourceSettings.Url,
	}
	teams.TeamsSettings = buildSettings(sourceSettings)
	return teams
}

func buildServiceNow(sourceSettings *PluginSettings) *plugins.ServiceNowPlugin {
	serviceNow := &plugins.ServiceNowPlugin{
		User:     sourceSettings.User,
		Password: sourceSettings.Password,
		Table:    sourceSettings.BoardName,
		Instance: sourceSettings.InstanceName,
	}
	serviceNow.ServiceNowSettings = buildSettings(sourceSettings)

	if len(serviceNow.Table) == 0 {
		serviceNow.Table = ServiceNowTableDefault
	}

	return serviceNow
}

func buildSlackPlugin(sourceSettings *PluginSettings) *plugins.SlackPlugin {
	slack := &plugins.SlackPlugin{}
	slack.Url = sourceSettings.Url
	slack.SlackSettings = buildSettings(sourceSettings)
	return slack
}

func buildEmailPlugin(sourceSettings *PluginSettings) *plugins.EmailPlugin {
	em := &plugins.EmailPlugin{
		User:       sourceSettings.User,
		Password:   sourceSettings.Password,
		Host:       sourceSettings.Host,
		Port:       sourceSettings.Port,
		Sender:     sourceSettings.Sender,
		Recipients: sourceSettings.Recipients,
		UseMX:      sourceSettings.UseMX,
	}
	em.EmailSettings = buildSettings(sourceSettings)
	return em
}

func buildJiraPlugin(sourceSettings *PluginSettings) *plugins.JiraAPI {
	jiraApi := &plugins.JiraAPI{
		Url:             sourceSettings.Url,
		User:            sourceSettings.User,
		Password:        sourceSettings.Password,
		TlsVerify:       sourceSettings.TlsVerify,
		Issuetype:       sourceSettings.IssueType,
		ProjectKey:      strings.ToUpper(sourceSettings.ProjectKey),
		Priority:        sourceSettings.Priority,
		Assignee:        sourceSettings.Assignee,
		FixVersions:     sourceSettings.FixVersions,
		AffectsVersions: sourceSettings.AffectsVersions,
		Labels:          sourceSettings.Labels,
		Unknowns:        sourceSettings.Unknowns,
		SprintName:      sourceSettings.Sprint,
		SprintId:        -1,
		BoardName:       sourceSettings.BoardName,
	}
	if jiraApi.Issuetype == "" {
		jiraApi.Issuetype = IssueTypeDefault
	}

	if jiraApi.Priority == "" {
		jiraApi.Priority = PriorityDefault
	}

	if len(jiraApi.Assignee) == 0 {
		jiraApi.Assignee = []string{jiraApi.User}
	}
	jiraApi.JiraSettings = buildSettings(sourceSettings)
	return jiraApi
}

func Instance() *AlertMgr {
	initCtx.Do(func() {
		alertmgrCtx = &AlertMgr{
			mutex:   sync.Mutex{},
			quit:    make(chan struct{}),
			queue:   make(chan string, 1000),
			plugins: make(map[string]plugins.Plugin),
		}
	})
	return alertmgrCtx
}

func (ctx *AlertMgr) Start(cfgfile string) {
	log.Printf("Starting AlertMgr....")
	ctx.cfgfile = cfgfile
	ctx.load()
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

func (ctx *AlertMgr) Send(data string) {
	ctx.mutex.Lock()
	defer ctx.mutex.Unlock()
	ctx.queue <- data
}

func (ctx *AlertMgr) load() error {
	ctx.mutex.Lock()
	defer ctx.mutex.Unlock()
	log.Printf("Loading alerts configuration file %s ....\n", ctx.cfgfile)
	data, err := ioutil.ReadFile(ctx.cfgfile)
	if err != nil {
		log.Printf("Failed to open file %s, %s", ctx.cfgfile, err)
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
		utils.Debug("%#v\n", settings)
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

func (ctx *AlertMgr) listen() {
	for {
		select {
		case <-ctx.quit:
			return
		case data := <-ctx.queue:
			service := new(scanservice.ScanService)
			go service.ResultHandling(strings.ReplaceAll(data, "`", "'"), ctx.plugins)
		}
	}
}
