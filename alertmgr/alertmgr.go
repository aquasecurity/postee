package alertmgr

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/aquasecurity/postee/dbservice"
	"github.com/aquasecurity/postee/routes"
	"io/ioutil"
	"log"
	"os"
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
	mutexScan   sync.Mutex
	mutexEvent  sync.Mutex
	quit        chan struct{}
	queue       chan []byte
	events      chan string
	cfgfile     string
	aquaServer  string
	plugins     map[string]plugins.Plugin
	inputRoutes map[string]*routes.InputRoutes
}

var initCtx sync.Once
var alertmgrCtx *AlertMgr
var baseForTicker = time.Hour
var ticker *time.Ticker

var osStat = os.Stat

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
		}
	})
	return alertmgrCtx
}

func (ctx *AlertMgr) Start(cfgfile string) error {
	log.Printf("Starting AlertMgr....")
	ctx.cfgfile = cfgfile
	ctx.load()
	go ctx.listen()
	return nil
}

func (ctx *AlertMgr) Terminate() {
	log.Printf("Terminating AlertMgr....")
	close(ctx.quit)
	for _, pl := range ctx.plugins {
		pl.Terminate()
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
		ticker = time.NewTicker(baseForTicker * time.Duration(tenant.DBTestInterval))
		go func() {
			for range ticker.C {
				dbservice.CheckSizeLimit()
				dbservice.CheckExpiredData()
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
	ignoreAuthorization := map[string]bool{
		"slack":   true,
		"teams":   true,
		"webhook": true,
		"email":   true,
		"splunk":  true,
	}

	for _, settings := range tenant.Outputs {
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
				ctx.plugins[settings.Name] = buildJiraPlugin(&settings)
			case "email":
				ctx.plugins[settings.Name] = buildEmailPlugin(&settings)
			case "slack":
				ctx.plugins[settings.Name] = buildSlackPlugin(&settings, ctx.aquaServer)
			case "teams":
				ctx.plugins[settings.Name] = buildTeamsPlugin(&settings, ctx.aquaServer)
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
