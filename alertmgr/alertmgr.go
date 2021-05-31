package alertmgr

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/aquasecurity/postee/data"
	"github.com/aquasecurity/postee/dbservice"
	"github.com/aquasecurity/postee/layout"
	"github.com/aquasecurity/postee/outputs"
	"github.com/aquasecurity/postee/regoservice"
	"github.com/aquasecurity/postee/routes"
	"github.com/aquasecurity/postee/scanservice"
	"github.com/aquasecurity/postee/utils"
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
	outputs     map[string]outputs.Output
	inputRoutes map[string]*routes.InputRoute
	templates   map[string]data.Inpteval
}

var (
	errNoOutputs  = errors.New("there aren't started outputs")
	initCtx       sync.Once
	alertmgrCtx   *AlertMgr
	baseForTicker = time.Hour

	osStat = os.Stat

	ignoreAuthorization = map[string]bool{
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
			outputs:     make(map[string]outputs.Output),
			inputRoutes: make(map[string]*routes.InputRoute),
			templates:   make(map[string]data.Inpteval),
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
	ctx.outputs = map[string]outputs.Output{}
	err := ctx.load()
	if err != nil {
		return err
	}
	go ctx.listen()
	return nil
}

func (ctx *AlertMgr) Terminate() {
	log.Printf("Terminating AlertMgr....")

	ctx.quit <- struct{}{}
	ctx.stopTicker <- struct{}{}

	for _, pl := range ctx.outputs {
		pl.Terminate()
	}
}

func (ctx *AlertMgr) Event(data string) {
	ctx.mutexEvent.Lock()
	defer ctx.mutexEvent.Unlock()
	ctx.events <- data
}

func (ctx *AlertMgr) SendByRoute(route string, payload []byte) {
	ctx.mutexScan.Lock()
	defer ctx.mutexScan.Unlock()
	ctx.handleRoute(route, payload)
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
	tenant, err := Parsev2cfg(ctx.cfgfile)

	if err != nil {
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

	for i, r := range tenant.InputRoutes {
		log.Printf("Configuring route %s \n", r.Name)
		ctx.inputRoutes[r.Name] = buildRoute(&tenant.InputRoutes[i])
	}
	for _, t := range tenant.Templates {
		template := &t
		log.Printf("Configuring template %s \n", template.Name)

		if template.LegacyScanRenderer != "" {
			inpteval, err := layout.BuildLegacyScnEvaluator(template.LegacyScanRenderer)
			if err != nil {
				return err
			}
			ctx.templates[t.Name] = inpteval
			log.Printf("Configured with legacy renderer %s \n", template.LegacyScanRenderer)
		}

		if template.RegoPackage != "" {
			inpteval, err := regoservice.BuildBundledRegoEvaluator(template.RegoPackage)
			if err != nil {
				return err
			}
			ctx.templates[t.Name] = inpteval
			log.Printf("Configured with Rego package %s\n", template.RegoPackage)
		}
		if template.Url != "" {
			log.Printf("Configured with url: %s\n", template.Url)

			r, err := http.NewRequest("GET", template.Url, nil)
			if err != nil {
				return err
			}
			resp, err := http.DefaultClient.Do(r)
			if err != nil {
				return err
			}

			if resp.StatusCode > 399 {
				return errors.New(fmt.Sprintf("can not connect to %s, response status is %d", template.Url, resp.StatusCode))
			}

			b, err := ioutil.ReadAll(resp.Body)
			defer resp.Body.Close()
			if err != nil {
				return err
			}
			inpteval, err := regoservice.BuildExternalRegoEvaluator(path.Base(r.URL.Path), string(b))

			if err != nil {
				return err
			}

			ctx.templates[t.Name] = inpteval
		}
		//body goes last to provide an option to keep body in config but not use it
		if template.Body != "" {
			inpteval, err := regoservice.BuildExternalRegoEvaluator("inline.rego", template.Body)
			if err != nil {
				return err
			}
			ctx.templates[t.Name] = inpteval
		}
	}

	for name, output := range ctx.outputs {
		if output != nil {
			ctx.outputs[name] = nil
			output.Terminate()
		}
	}

	for _, settings := range tenant.Outputs {
		utils.Debug("%#v\n", anonymizeSettings(&settings))

		if settings.Enable {
			plg := BuildAndInitOtpt(&settings, ctx.aquaServer)
			if plg != nil {
				log.Printf("Output %s is configured", settings.Name)
				ctx.outputs[settings.Name] = plg
			}
		}
	}
	return nil
}

type service interface {
	ResultHandling(input []byte, name *string, output outputs.Output, route *routes.InputRoute, inpteval data.Inpteval, aquaServer *string)
}

var getScanService = func() service {
	serv := &scanservice.ScanService{}
	return serv
}

func (ctx *AlertMgr) handleRoute(routeName string, in []byte) {
	r, ok := ctx.inputRoutes[routeName]
	if !ok || r == nil {
		log.Printf("There isn't route %q", routeName)
		return
	}
	if len(r.Outputs) == 0 {
		log.Printf("route %q has no outputs", routeName)
		return
	}
	for _, outputName := range r.Outputs {
		pl, ok := ctx.outputs[outputName]
		if !ok {
			log.Printf("route %q contains an output %q, which doesn't enable now.", routeName, outputName)
			continue
		}
		tmpl, ok := ctx.templates[r.Template]
		if !ok {
			log.Printf("route %q contains a template %q, which is undefined.",
				routeName, r.Template)
			continue
		}
		log.Printf("route %q is associated with template %q", routeName, r.Template)
		go getScanService().ResultHandling(in, &routeName, pl, r, tmpl, &ctx.aquaServer)
	}
}

func (ctx *AlertMgr) handle(in []byte) {
	for routeName := range ctx.inputRoutes {
		ctx.handleRoute(routeName, in)
	}
}
func BuildAndInitOtpt(settings *OutputSettings, aquaServerUrl string) outputs.Output {
	var plg outputs.Output

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

	utils.Debug("Starting Output %q: %q\n", settings.Type, settings.Name)

	switch settings.Type {
	case "jira":
		plg = buildJiraOutput(settings)
	case "email":
		plg = buildEmailOutput(settings)
	case "slack":
		plg = buildSlackOutput(settings, aquaServerUrl)
	case "teams":
		plg = buildTeamsOutput(settings, aquaServerUrl)
	case "serviceNow":
		plg = buildServiceNow(settings)
	case "webhook":
		plg = buildWebhookOutput(settings)
	case "splunk":
		plg = buildSplunkOutput(settings)
	default:
		log.Printf("Output type %q is undefined or empty. Output name is %q.",
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
