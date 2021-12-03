package router

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/dbservice"
	"github.com/aquasecurity/postee/v2/formatting"
	"github.com/aquasecurity/postee/v2/msgservice"
	"github.com/aquasecurity/postee/v2/outputs"
	"github.com/aquasecurity/postee/v2/regoservice"
	"github.com/aquasecurity/postee/v2/routes"
	"github.com/aquasecurity/postee/v2/utils"
	"golang.org/x/xerrors"
)

const (
	IssueTypeDefault = "Task"
	PriorityDefault  = "High"

	ServiceNowTableDefault = "incident"
	AnonymizeReplacement   = "<hidden>"
)

type Router struct {
	mutexScan      sync.Mutex
	quit           chan struct{}
	queue          chan []byte
	ticker         *time.Ticker
	stopTicker     chan struct{}
	cfgfile        string
	aquaServer     string
	outputs        map[string]outputs.Output
	inputRoutes    map[string]*routes.InputRoute
	templates      map[string]data.Inpteval
	synchronous    bool
	inputCallBacks map[string][]InputCallbackFunc
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
			outputs:     make(map[string]outputs.Output),
			inputRoutes: make(map[string]*routes.InputRoute),
			templates:   make(map[string]data.Inpteval),
			synchronous: false,
		}
	})
	return routerCtx
}
func (ctx *Router) ReloadConfig() {
	ctx.Terminate()
	err := ctx.ApplyFileCfg(ctx.cfgfile, ctx.synchronous)

	if err != nil {
		log.Printf("Unable to start router: %s", err)
	}
}

func (ctx *Router) initCfg(synchronous bool) {
	ctx.cleanInstance()

	ctx.synchronous = synchronous

	if !ctx.synchronous {
		ctx.quit = make(chan struct{})
		ctx.queue = make(chan []byte, 1000)
		ctx.stopTicker = make(chan struct{})
	} else {
		ctx.quit = nil
		ctx.queue = nil
		ctx.stopTicker = nil
	}
}

func (ctx *Router) ApplyFileCfg(cfgfile string, synchronous bool) error {
	log.Printf("Starting Router....")

	ctx.cfgfile = cfgfile

	ctx.initCfg(synchronous)

	err := ctx.load()
	if err != nil {
		return err
	}

	if !ctx.synchronous {
		go ctx.listen()
	}

	return nil
}

func (ctx *Router) Terminate() {
	log.Printf("Terminating Router....")

	for _, pl := range ctx.outputs {
		err := pl.Terminate()
		if err != nil {
			log.Printf("failed to terminate output: %v", err)
		}
	}
	log.Printf("Outputs terminated")

	for _, route := range ctx.inputRoutes {
		route.StopScheduler()
	}
	log.Printf("Route schedulers stopped")

	log.Printf("ctx.quit %v\n", ctx.quit)

	if ctx.quit != nil {
		ctx.quit <- struct{}{}
	}

	log.Printf("quit notified")

	if ctx.ticker != nil {
		ctx.stopTicker <- struct{}{}
		log.Printf("stopTicker notified")
	}

	ctx.cleanInstance()
}
func (ctx *Router) cleanInstance() {
	ctx.outputs = map[string]outputs.Output{}
	ctx.inputRoutes = map[string]*routes.InputRoute{}
	ctx.templates = map[string]data.Inpteval{}
	ctx.inputCallBacks = map[string][]InputCallbackFunc{}

	ctx.ticker = nil
	ctx.quit = nil
}

func (ctx *Router) Send(data []byte) {
	ctx.queue <- data
}
func (ctx *Router) deleteTemplate(name string, removeFromRoutes bool) error {
	_, ok := ctx.outputs[name]
	if !ok {
		return xerrors.Errorf("template %s is not found", name)
	}
	delete(ctx.outputs, name)

	if removeFromRoutes {
		for _, route := range ctx.inputRoutes {
			if route.Template == name {
				route.Template = ""
			}
		}
	}

	return nil
}

func (ctx *Router) initTemplate(template *data.Template) error {
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
			return xerrors.Errorf("can not connect to %s, response status is %d", template.Url, resp.StatusCode)
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
func (ctx *Router) setAquaServerUrl(url string) {
	if len(url) > 0 {
		var slash string
		if !strings.HasSuffix(url, "/") {
			slash = "/"
		}
		ctx.aquaServer = fmt.Sprintf("%s%s#/images/", url, slash)
	}

}

func (ctx *Router) load() error {
	ctx.mutexScan.Lock()
	defer ctx.mutexScan.Unlock()
	log.Printf("Loading alerts configuration file %s ....\n", ctx.cfgfile)
	tenant, err := Parsev2cfg(ctx.cfgfile)

	if err != nil {
		return err
	}

	ctx.setAquaServerUrl(tenant.AquaServer)
	//----------------------------------------------------
	// TODO there should be some other way of doing that

	if err = dbservice.ConfigureDb(tenant.Name, &tenant.DBTestInterval, tenant.DBMaxSize); err != nil {
		return err
	}

	ctx.ticker = time.NewTicker(baseForTicker * time.Duration(tenant.DBTestInterval))
	go func() {
		for {
			select {
			case <-ctx.stopTicker:
				return
			case <-ctx.ticker.C:
				dbservice.Db.CheckSizeLimit()
				dbservice.Db.CheckExpiredData()
			}
		}
	}()

	//----------------------------------------------------

	for i := range tenant.InputRoutes {
		ctx.addRoute(&tenant.InputRoutes[i])
	}
	for _, t := range tenant.Templates {
		err := ctx.initTemplate(&t)
		if err != nil {
			log.Printf("Can not initialize template %s: %v \n", t.Name, err)
		}
	}

	for _, settings := range tenant.Outputs {
		utils.Debug("%#v\n", anonymizeSettings(&settings))

		err = ctx.addOutput(&settings)

		if err != nil {
			log.Printf("Can not initialize output %s: %v \n", settings.Name, err)
		} else {
			log.Printf("Output %s is configured", settings.Name)
		}

	}
	return nil
}
func (ctx *Router) setInputCallbackFunc(routeName string, callback InputCallbackFunc) {
	inputCallBacks := ctx.inputCallBacks[routeName]
	inputCallBacks = append(inputCallBacks, callback)

	ctx.inputCallBacks[routeName] = inputCallBacks
}

func (ctx *Router) addRoute(r *routes.InputRoute) {
	ctx.inputRoutes[r.Name] = routes.ConfigureAggrTimeout(r)
}

func (ctx *Router) deleteRoute(name string) error {
	r, ok := ctx.inputRoutes[name]
	if !ok {
		return xerrors.Errorf("output %s is not found", name)
	}
	r.StopScheduler()
	delete(ctx.inputRoutes, name)
	delete(ctx.inputCallBacks, name)

	return nil
}

func (ctx *Router) listRoutes() []routes.InputRoute {
	list := make([]routes.InputRoute, 0, len(ctx.inputRoutes))
	for _, r := range ctx.inputRoutes {
		list = append(list, routes.InputRoute{
			Name:    r.Name,
			Input:   r.Input,
			Outputs: data.CopyStringArray(r.Outputs),
			Plugins: routes.Plugins{
				AggregateIssuesNumber:   r.Plugins.AggregateIssuesNumber,
				AggregateIssuesTimeout:  r.Plugins.AggregateIssuesTimeout,
				PolicyShowAll:           r.Plugins.PolicyShowAll,
				AggregateTimeoutSeconds: r.Plugins.AggregateTimeoutSeconds,
			},
			Template: r.Template,
		})
	}
	return list
}

func (ctx *Router) addOutput(settings *data.OutputSettings) error {
	if settings.Enable {
		plg, err := buildAndInitOtpt(settings, ctx.aquaServer)

		if err != nil {
			return err
		}

		ctx.outputs[settings.Name] = plg

	}
	return nil
}
func (ctx *Router) deleteOutput(outputName string, removeFromRoutes bool) error {
	output, ok := ctx.outputs[outputName]
	if !ok {
		return xerrors.Errorf("output %s is not found", outputName)
	}
	output.Terminate()
	delete(ctx.outputs, outputName)

	if removeFromRoutes {
		for _, route := range ctx.inputRoutes {
			removeOutputFromRoute(route, outputName)
		}
	}

	return nil
}
func (ctx *Router) listOutputs() []data.OutputSettings {
	r := make([]data.OutputSettings, 0)
	for _, output := range ctx.outputs {
		r = append(r, *output.CloneSettings())
	}
	return r
}
func removeOutputFromRoute(r *routes.InputRoute, outputName string) {
	filtered := make([]string, 0)
	for _, n := range r.Outputs {
		if n != outputName {
			filtered = append(filtered, n)
		}
	}
	r.Outputs = filtered
}

type service interface {
	MsgHandling(input map[string]interface{}, output outputs.Output, route *routes.InputRoute, inpteval data.Inpteval, aquaServer *string)
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
	if len(r.Outputs) == 0 {
		log.Printf("route %q has no outputs", routeName)
		return
	}

	if !getScanService().EvaluateRegoRule(r, in) {
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
			log.Printf("route %q contains reference to undefined or misconfigured template %q.",
				routeName, r.Template)
			continue
		}
		log.Printf("route %q is associated with template %q", routeName, r.Template)

		if ctx.synchronous {
			getScanService().MsgHandling(inMsg, pl, r, tmpl, &ctx.aquaServer)
		} else {
			go getScanService().MsgHandling(inMsg, pl, r, tmpl, &ctx.aquaServer)
		}
	}
}

func (ctx *Router) handle(in []byte) {
	for routeName := range ctx.inputRoutes {
		ctx.HandleRoute(routeName, in)
	}
}
func buildAndInitOtpt(settings *data.OutputSettings, aquaServerUrl string) (outputs.Output, error) {
	settings.User = utils.GetEnvironmentVarOrPlain(settings.User)
	if len(settings.User) == 0 && requireAuthorization[settings.Type] {
		return nil, xerrors.Errorf("user for %q is empty", settings.Name)
	}
	settings.Password = utils.GetEnvironmentVarOrPlain(settings.Password)
	if len(settings.Password) == 0 && requireAuthorization[settings.Type] {
		return nil, xerrors.Errorf("password for %q is empty", settings.Name)
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

	utils.Debug("Starting Output %q: %q\n", settings.Type, settings.Name)

	var plg outputs.Output

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
	case "stdout":
		plg = buildStdoutOutput(settings)
	default:
		return nil, xerrors.Errorf("output %s has undefined or empty type: %q", settings.Name, settings.Type)
	}
	err := plg.Init()
	if err != nil {
		log.Printf("failed to Init : %v", err)
	}

	return plg, nil
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
