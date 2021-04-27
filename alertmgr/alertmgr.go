package alertmgr

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aquasecurity/postee/dbservice"
	"github.com/aquasecurity/postee/routes"

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

type AlertMgr struct {
	mutexScan   sync.Mutex
	mutexEvent  sync.Mutex
	quit        chan struct{}
	queue       chan []byte
	ticker      *time.Ticker
	stopTicker  chan struct{}
	events      chan string
	cfgfile     string
	aquaServer  string
	plugins     map[string]plugins.Plugin
	inputRoutes map[string]*routes.InputRoutes
}

var (
	errNoPlugins  = errors.New("there aren't started plugins")
	initCtx       sync.Once
	alertmgrCtx   *AlertMgr
	baseForTicker = time.Hour

	osStat = os.Stat

	ignoreAuthorization map[string]bool = map[string]bool{
		"slack":   true,
		"teams":   true,
		"webhook": true,
		"email":   true,
		"splunk":  true,
	}
)

func Instance() *AlertMgr {
	initCtx.Do(func() {
		alertmgrCtx = &AlertMgr{
			mutexScan:   sync.Mutex{},
			mutexEvent:  sync.Mutex{},
			quit:        make(chan struct{}),
			events:      make(chan string, 1000),
			queue:       make(chan []byte, 1000),
			plugins:     make(map[string]plugins.Plugin),
			inputRoutes: make(map[string]*routes.InputRoutes),
			stopTicker:  make(chan struct{}),
		}
	})
	return alertmgrCtx
}
func (ctx *AlertMgr) ReloadConfig() {
	ctx.Terminate()
	ctx.Start(ctx.cfgfile)
}

func (ctx *AlertMgr) Start(cfgfile string) error {
	log.Printf("Starting AlertMgr....")
	ctx.cfgfile = cfgfile
	ctx.plugins = map[string]plugins.Plugin{}
	ctx.load()
	go ctx.listen()
	return nil
}

func (ctx *AlertMgr) Terminate() {
	log.Printf("Terminating AlertMgr....")

	ctx.quit <- struct{}{}
	ctx.stopTicker <- struct{}{}

	for _, pl := range ctx.plugins {
		pl.Terminate()
	}
}

func (ctx *AlertMgr) Event(data string) {
	ctx.mutexEvent.Lock()
	defer ctx.mutexEvent.Unlock()
	ctx.events <- data
}

func (ctx *AlertMgr) Send(data []byte) {
	ctx.mutexScan.Lock()
	defer ctx.mutexScan.Unlock()
	ctx.queue <- data
}

func (ctx *AlertMgr) load() error {
	ctx.mutexScan.Lock()
	defer ctx.mutexScan.Unlock()
	log.Printf("Loading alerts configuration file %s ....\n", ctx.cfgfile)
	data, err := ioutil.ReadFile(ctx.cfgfile)
	if err != nil {
		log.Printf("Failed to open file %s, %s", ctx.cfgfile, err)
		return err
	}
	tenant := &TenantSettings{}
	err = yaml.Unmarshal(data, tenant)
	if err != nil {
		log.Printf("Failed yaml.Unmarshal, %s", err)
		return err
	}

	if len(tenant.AquaServer) > 0 {
		var slash string
		if !strings.HasSuffix(tenant.AquaServer, "/") {
			slash = "/"
		}
		ctx.aquaServer = fmt.Sprintf("%s%s#/images/", tenant.AquaServer, slash)
	}

	dbservice.DbSizeLimit = tenant.DBMaxSize
	dbservice.DbDueDate = tenant.DBRemoveOldData
	if tenant.DBTestInterval == 0 {
		tenant.DBTestInterval = 1
	}
	if dbservice.DbSizeLimit != 0 || dbservice.DbDueDate != 0 {
		ctx.ticker = time.NewTicker(baseForTicker * time.Duration(tenant.DBTestInterval))
		go func() {
			for {
				select {
				case <-ctx.stopTicker:
					return
				case <-ctx.ticker.C:
					dbservice.CheckSizeLimit()
					dbservice.CheckExpiredData()
				}
			}
		}()
	}

	for _, r := range tenant.InputRoutes {
		ctx.inputRoutes[r.Name] = buildRoute(&r)
	}

	for name, plugin := range ctx.plugins {
		if plugin != nil {
			ctx.plugins[name] = nil
			plugin.Terminate()
		}
	}

	for _, settings := range tenant.Outputs {
		utils.Debug("%#v\n", anonymizeSettings(&settings))

		if settings.Enable {
			plg := BuildAndInitPlg(&settings, ctx)
			if plg != nil {
				ctx.plugins[settings.Name] = plg
			}
		}
	}
	return nil
}

type service interface {
	ResultHandling(input []byte, name *string, plugin plugins.Plugin, route *routes.InputRoutes, aquaServer *string)
}

var getScanService = func() service {
	serv := &scanservice.ScanService{}
	return serv
}

func (ctx *AlertMgr) handle(in []byte) {
	for routeName, r := range ctx.inputRoutes {
		pl, ok := ctx.plugins[r.Output]
		if !ok {
			log.Printf("route %q contains an output %q, which doesn't enable now.", routeName, r.Output)
			continue
		}
		go getScanService().ResultHandling(in, &routeName, pl, r, &ctx.aquaServer)
	}
}
func BuildAndInitPlg(settings *PluginSettings, ctx *AlertMgr) plugins.Plugin {
	var plg plugins.Plugin

	settings.User = utils.GetEnvironmentVarOrPlain(settings.User)
	if len(settings.User) == 0 && !ignoreAuthorization[settings.Type] {
		log.Printf("User for %q is empty", settings.Name)
		return nil
	}
	settings.Password = utils.GetEnvironmentVarOrPlain(settings.Password)
	if len(settings.Password) == 0 && !ignoreAuthorization[settings.Type] {
		log.Printf("Password for %q is empty", settings.Name)
		return nil
	}

	utils.Debug("Starting Plugin %q: %q\n", settings.Type, settings.Name)

	switch settings.Type {
	case "jira":
		plg = buildJiraPlugin(settings)
	case "email":
		plg = buildEmailPlugin(settings)
	case "slack":
		plg = buildSlackPlugin(settings, ctx.aquaServer)
	case "teams":
		plg = buildTeamsPlugin(settings, ctx.aquaServer)
	case "serviceNow":
		plg = buildServiceNow(settings)
	case "webhook":
		plg = buildWebhookPlugin(settings)
	case "splunk":
		plg = buildSplunkPlugin(settings)
	default:
		log.Printf("Plugin type %q is undefined or empty. Plugin name is %q.",
			settings.Type, settings.Name)
		return nil
	}
	plg.Init()

	return plg
}

func (ctx *AlertMgr) listen() {
	for {
		select {
		case <-ctx.quit:
			return
		case data := <-ctx.queue:
			go ctx.handle(bytes.ReplaceAll(data, []byte{'`'}, []byte{'\''}))
		}
	}
}
