package alertmgr

import (
	"errors"
	"fmt"
	"github.com/aquasecurity/postee/dbservice"
	"github.com/aquasecurity/postee/eventservice"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

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

var (
	errNoPlugins = errors.New("there aren't started plugins")
)

type AlertMgr struct {
	mutexScan  sync.Mutex
	mutexEvent sync.Mutex
	quit       chan struct{}
	queue      chan string
	events     chan string
	cfgFiles   []string
	plugins    map[string]map[string]plugins.Plugin
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
			plugins:    make(map[string]map[string]plugins.Plugin),
		}
	})
	return alertmgrCtx
}

func (ctx *AlertMgr) Start(files []string) error {
	log.Printf("Starting AlertMgr....")
	ctx.cfgFiles = files
	if err := ctx.load(); err != nil {
		return err
	}
	go ctx.listen()
	return nil
}

func (ctx *AlertMgr) TerminatePlugins(tenant string) {
	for _, pl := range ctx.plugins[tenant] {
		pl.Terminate()
	}
}

func (ctx *AlertMgr) Terminate() {
	log.Printf("Terminating AlertMgr....")
	close(ctx.quit)
	for name, _ := range ctx.plugins {
		ctx.TerminatePlugins(name)
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
	wasLoaded := false
	for _, file := range ctx.cfgFiles {
		log.Printf("Loading configuration file %q...\n", file)
		data, err := ioutil.ReadFile(file)
		if err != nil {
			log.Printf("Could't read from file %q: %s", file, err)
			continue
		}
		tenant := &TenantSettings{}
		err = yaml.Unmarshal(data, tenant)
		if err != nil {
			log.Printf("Failed yaml.Unmarshal from %q: %s", file, err)
			continue
		}

		if len(tenant.AquaServer) > 0 {
			var slash string
			if !strings.HasSuffix(tenant.AquaServer, "/") {
				slash = "/"
			}
			aquaServer = fmt.Sprintf("%s%s#/images/", tenant.AquaServer, slash)
		}
		dbservice.DbSizeLimit = tenant.DBMaxSize
		dbservice.DbDueDate = tenant.DBRemoveOldData

		if tenant.DBTestInterval == 0 {
			tenant.DBTestInterval = 1
		}

		if dbservice.DbSizeLimit != 0 || dbservice.DbDueDate != 0 {
			ticker = time.NewTicker(baseForTicker * time.Duration(tenant.DBTestInterval))
			go func() {
				for range ticker.C {
					dbservice.CheckSizeLimit()
					dbservice.CheckExpiredData()
				}
			}()
		}
		name := tenant.Name
		if name == "" {
			name = filepath.Base(file)
		}
		ctx.plugins[name] = make(map[string]plugins.Plugin)
		if err := ctx.loadIntegrations(name, tenant.Integrations); err != nil {
			log.Printf("load integration from %q error: %v", file, err)
			continue
		}
		if len(ctx.plugins[name]) == 0 {
			log.Printf("There aren't started plugins for %q (%q)", name, file)
		} else {
			wasLoaded = true
		}
	}
	if !wasLoaded {
		return errNoPlugins
	}
	return nil
}

func (ctx *AlertMgr) loadIntegrations(name string, pluginSettings []PluginSettings) error {
	ctx.mutexScan.Lock()
	defer ctx.mutexScan.Unlock()
	ctx.TerminatePlugins(name)

	ignoreAuthorization := map[string]bool{
		"slack":   true,
		"teams":   true,
		"webhook": true,
		"email":   true,
		"splunk":  true,
	}

	for _, settings := range pluginSettings {
		utils.Debug("%#v\n", anonymizeSettings(&settings))

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
				ctx.plugins[name][settings.Name] = buildJiraPlugin(&settings)
			case "email":
				ctx.plugins[name][settings.Name] = buildEmailPlugin(&settings)
			case "slack":
				ctx.plugins[name][settings.Name] = buildSlackPlugin(&settings)
			case "teams":
				ctx.plugins[name][settings.Name] = buildTeamsPlugin(&settings)
			case "serviceNow":
				ctx.plugins[name][settings.Name] = buildServiceNow(&settings)
			case "webhook":
				ctx.plugins[name][settings.Name] = buildWebhookPlugin(&settings)
			case "splunk":
				ctx.plugins[name][settings.Name] = buildSplunkPlugin(&settings)
			default:
				log.Printf("Plugin type %q is undefined or empty. Plugin name is %q.",
					settings.Type, settings.Name)
				continue
			}
			ctx.plugins[name][settings.Name].Init()
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
			for _, pl := range ctx.plugins {
				go getScanService().ResultHandling(strings.ReplaceAll(data, "`", "'"), pl)
			}
			//		case event := <-ctx.events:
			//			go getEventService().ResultHandling(event, ctx.plugins)
		}
	}
}
