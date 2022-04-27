package router

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/aquasecurity/postee/v2/actions"
	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/dbservice"
	"github.com/aquasecurity/postee/v2/formatting"
	"github.com/aquasecurity/postee/v2/msgservice"
	"github.com/aquasecurity/postee/v2/regoservice"
	"github.com/aquasecurity/postee/v2/routes"
	"github.com/aquasecurity/postee/v2/utils"
)

const (
	ServiceNowTableDefault = "incident"
	AnonymizeReplacement   = "<hidden>"
)

type Router struct {
	mutexScan   sync.Mutex
	quit        chan struct{}
	queue       chan []byte
	ticker      *time.Ticker
	stopTicker  chan struct{}
	cfgfile     string
	aquaServer  string
	actions     map[string]actions.Action
	inputRoutes map[string]*routes.InputRoute
	templates   map[string]data.Inpteval
}

var (
	initCtx       sync.Once
	routerCtx     *Router
	baseForTicker = time.Hour

	requireAuthorization = map[string]bool{
		"servicenow": true,
	}
)

func Instance() *Router {
	initCtx.Do(func() {
		routerCtx = &Router{
			mutexScan:   sync.Mutex{},
			quit:        make(chan struct{}),
			queue:       make(chan []byte, 1000),
			actions:     make(map[string]actions.Action),
			inputRoutes: make(map[string]*routes.InputRoute),
			templates:   make(map[string]data.Inpteval),
			stopTicker:  make(chan struct{}),
		}
	})
	return routerCtx
}
func (ctx *Router) ReloadConfig() {
	ctx.Terminate()
	err := ctx.Start(ctx.cfgfile)

	if err != nil {
		log.Printf("Unable to start router: %s", err)
	}
}

func (ctx *Router) Start(cfgfile string) error {
	log.Printf("Starting Router....")

	ctx.cfgfile = cfgfile
	ctx.actions = map[string]actions.Action{}
	ctx.inputRoutes = map[string]*routes.InputRoute{}
	ctx.templates = map[string]data.Inpteval{}
	ctx.ticker = nil

	err := ctx.load()
	if err != nil {
		return err
	}
	go ctx.listen()
	return nil
}

func (ctx *Router) Terminate() {
	log.Printf("Terminating Router....")

	for _, pl := range ctx.actions {
		err := pl.Terminate()
		if err != nil {
			log.Printf("failed to terminate output: %v", err)
		}
	}
	log.Printf("Actions terminated")

	for _, route := range ctx.inputRoutes {
		route.StopScheduler()
	}
	log.Printf("Route schedulers stopped")

	ctx.quit <- struct{}{}
	log.Printf("quit notified")
	if ctx.ticker != nil {
		ctx.stopTicker <- struct{}{}
		log.Printf("stopTicker notified")
	}

}

func (ctx *Router) Send(data []byte) {
	ctx.queue <- data
}

func (ctx *Router) initTemplate(template *Template) error {
	log.Printf("Configuring template %s \n", template.Name)

	if template.LegacyScanRenderer != "" {
		inpteval, err := formatting.BuildLegacyScnEvaluator(template.LegacyScanRenderer)
		if err != nil {
			return err
		}
		ctx.templates[template.Name] = inpteval
		log.Printf("Configured with legacy renderer %s \n", template.LegacyScanRenderer)
	}

	if template.RegoPackage != "" {
		inpteval, err := regoservice.BuildBundledRegoEvaluator(template.RegoPackage)
		if err != nil {
			return err
		}
		ctx.templates[template.Name] = inpteval
		log.Printf("Configured with Rego package %s\n", template.RegoPackage)
	}
	if template.Url != "" {
		log.Printf("Configured with url: %s\n", template.Url)

		r, err := http.NewRequest("GET", template.Url, nil)
		if err != nil {
			return err
		}
		httpClient := getHttpClient()
		resp, err := httpClient.Do(r)
		if err != nil {
			return err
		}

		if resp.StatusCode > 399 {
			return errors.New(fmt.Sprintf("can not connect to %s, response status is %d", template.Url, resp.StatusCode))
		}

		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		inpteval, err := regoservice.BuildExternalRegoEvaluator(path.Base(r.URL.Path), string(b))

		if err != nil {
			return err
		}

		ctx.templates[template.Name] = inpteval
	}
	//body goes last to provide an option to keep body in config but not use it
	if template.Body != "" {
		inpteval, err := regoservice.BuildExternalRegoEvaluator("inline.rego", template.Body)
		if err != nil {
			return err
		}
		ctx.templates[template.Name] = inpteval
	}
	return nil
}

func (ctx *Router) load() error {
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

	dbservice.DbSizeLimit = parseSize(tenant.DBMaxSize)
	if tenant.DBTestInterval == 0 {
		tenant.DBTestInterval = 1
	}
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

	for i, r := range tenant.InputRoutes {
		ctx.inputRoutes[r.Name] = routes.ConfigureTimeouts(&tenant.InputRoutes[i])
	}
	for _, t := range tenant.Templates {
		err := ctx.initTemplate(&t)
		if err != nil {
			log.Printf("Can not initialize template %s: %v \n", t.Name, err)
		}
	}

	for _, settings := range tenant.Actions {
		utils.Debug("%#v\n", anonymizeSettings(&settings))

		if settings.Enable {
			plg := BuildAndInitOtpt(&settings, ctx.aquaServer)
			if plg != nil {
				log.Printf("Action %s is configured", settings.Name)
				ctx.actions[settings.Name] = plg
			}
		}
	}
	return nil
}

type service interface {
	MsgHandling(input []byte, output actions.Action, route *routes.InputRoute, inpteval data.Inpteval, aquaServer *string)
	EvaluateRegoRule(input *routes.InputRoute, in []byte) bool
}

var getScanService = func() service {
	serv := &msgservice.MsgService{}
	return serv
}
var getHttpClient = func() *http.Client {
	return http.DefaultClient
}

func (ctx *Router) HandleRoute(routeName string, in []byte) {
	r, ok := ctx.inputRoutes[routeName]
	if !ok || r == nil {
		log.Printf("There isn't route %q", routeName)
		return
	}
	if len(r.Actions) == 0 {
		log.Printf("route %q has no actions", routeName)
		return
	}

	if !getScanService().EvaluateRegoRule(r, in) {
		return
	}

	for _, outputName := range r.Actions {
		pl, ok := ctx.actions[outputName]
		if !ok {
			log.Printf("route %q contains an action %q, which isn't enabled now.", routeName, outputName)
			continue
		}
		tmpl, ok := ctx.templates[r.Template]
		if !ok {
			log.Printf("route %q contains reference to undefined or misconfigured template %q.",
				routeName, r.Template)
			continue
		}
		log.Printf("route %q is associated with template %q", routeName, r.Template)

		if r.SerializeActions {
			getScanService().MsgHandling(in, pl, r, tmpl, &ctx.aquaServer)
		} else {
			go getScanService().MsgHandling(in, pl, r, tmpl, &ctx.aquaServer)
		}
	}
}

func (ctx *Router) handle(in []byte) {
	for routeName := range ctx.inputRoutes {
		ctx.HandleRoute(routeName, in)
	}
}
func BuildAndInitOtpt(settings *ActionSettings, aquaServerUrl string) actions.Action {
	settings.User = utils.GetEnvironmentVarOrPlain(settings.User)
	if len(settings.User) == 0 && requireAuthorization[settings.Type] {
		log.Printf("User for %q is empty", settings.Name)
		return nil
	}
	settings.Password = utils.GetEnvironmentVarOrPlain(settings.Password)
	if len(settings.Password) == 0 && requireAuthorization[settings.Type] {
		log.Printf("Password for %q is empty", settings.Name)
		return nil
	}
	settings.Token = utils.GetEnvironmentVarOrPlain(settings.Token)
	if settings.Type == "jira" {
		if len(settings.User) == 0 {
			log.Printf("User for %q is empty", settings.Name)
			return nil
		}
		if len(settings.Token) == 0 && len(settings.Password) == 0 {
			log.Printf("Password and Token for %q are empty", settings.Name)
			return nil
		}
	}

	utils.Debug("Starting Action %q: %q\n", settings.Type, settings.Name)

	var plg actions.Action
	var err error

	switch settings.Type {
	case "jira":
		plg = buildJiraAction(settings)
	case "email":
		plg = buildEmailAction(settings)
	case "slack":
		plg = buildSlackAction(settings, aquaServerUrl)
	case "teams":
		plg = buildTeamsAction(settings, aquaServerUrl)
	case "serviceNow":
		plg = buildServiceNow(settings)
	case "webhook":
		plg = buildWebhookAction(settings)
	case "splunk":
		plg = buildSplunkAction(settings)
	case "stdout":
		plg = buildStdoutAction(settings)
	case "nexusIq":
		plg = buildNexusIqAction(settings)
	case "exec":
		plg, err = buildExecAction(settings)
		if err != nil {
			log.Println(err.Error())
			return nil
		}
	case "http":
		plg, err = buildHTTPAction(settings)
		if err != nil {
			log.Println(err.Error())
			return nil
		}
	case "kubernetes":
		plg, err = buildKubernetesAction(settings)
		if err != nil {
			log.Println(err.Error())
			return nil
		}
	case "docker":
		plg, err = buildDockerAction(settings)
		if err != nil {
			log.Println(err.Error())
			return nil
		}
	default:
		log.Printf("Action type %q is undefined or empty. Action name is %q.",
			settings.Type, settings.Name)
		return nil
	}

	err = plg.Init()
	if err != nil {
		log.Printf("failed to Init : %v", err)
		return nil
	}

	return plg
}

func (ctx *Router) listen() {
	for {
		select {
		case <-ctx.quit:
			return
		case data := <-ctx.queue:
			go ctx.handle(bytes.ReplaceAll(data, []byte{'`'}, []byte{'\''}))
		}
	}
}
