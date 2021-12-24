package router

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/dbservice"
	"github.com/aquasecurity/postee/v2/dbservice/dbparam"
	"github.com/aquasecurity/postee/v2/dbservice/postgresdb"
	"github.com/aquasecurity/postee/v2/formatting"
	"github.com/aquasecurity/postee/v2/log"
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
	mutexScan              sync.Mutex
	quit                   chan struct{}
	queue                  chan []byte
	ticker                 *time.Ticker
	stopTicker             chan struct{}
	cfgfile                string
	aquaServer             string
	outputs                map[string]outputs.Output
	inputRoutes            map[string]*routes.InputRoute
	templates              map[string]data.Inpteval
	synchronous            bool
	inputCallBacks         map[string][]InputCallbackFunc
	databaseCfgCacheSource *data.TenantSettings
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
			mutexScan:              sync.Mutex{},
			outputs:                make(map[string]outputs.Output),
			inputRoutes:            make(map[string]*routes.InputRoute),
			templates:              make(map[string]data.Inpteval),
			synchronous:            false,
			databaseCfgCacheSource: &data.TenantSettings{},
		}
	})
	return routerCtx
}
func (ctx *Router) ReloadConfig() {
	ctx.Terminate()

	tenant, err := Parsev2cfg(ctx.cfgfile)
	if err != nil {
		log.Logger.Errorf("Failed to parse cfg file %s", err)
		return
	}

	err = ctx.applyTenantCfg(tenant, ctx.synchronous)

	if err != nil {
		log.Logger.Errorf("Unable to start router: %s", err)
	}
}

func (ctx *Router) cleanChannels(synchronous bool) {
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

func (ctx *Router) ApplyFileCfg(cfgfile, postgresUrl, pathToDb string, synchronous bool) error {
	log.Logger.Info("Starting Router....")

	ctx.cfgfile = cfgfile

	tenant, err := Parsev2cfg(ctx.cfgfile)
	if err != nil {
		return err
	}

	if err = dbservice.ConfigureDb(pathToDb, postgresUrl, tenant.Name); err != nil {
		return err
	}

	err = ctx.applyTenantCfg(tenant, synchronous)
	if err != nil {
		return err
	}
	return nil
}

func (ctx *Router) ApplyPostgresCfg(tenantName, postgresUrl string, synchronous bool) error {
	log.Logger.Info("Starting Router....")

	if err := dbservice.ConfigureDb("", postgresUrl, tenantName); err != nil {
		return err
	}

	tenant, err := ctx.loadCfgCacheSourceFromPostgres()
	if err != nil {
		return err
	}
	err = ctx.applyTenantCfg(tenant, synchronous)
	if err != nil {
		return err
	}
	return nil

}
func (ctx *Router) applyTenantCfg(tenant *data.TenantSettings, synchronous bool) error {
	ctx.cleanInstance()
	ctx.cleanChannels(synchronous)

	err := ctx.initTenantSettings(tenant)
	if err != nil {
		return err
	}

	if !ctx.synchronous {
		go ctx.listen()
	}

	return nil

}

func (ctx *Router) Terminate() {
	log.Logger.Info("Terminating Router....")

	for _, pl := range ctx.outputs {
		err := pl.Terminate()
		if err != nil {
			log.Logger.Errorf("failed to terminate output: %v", err)
		}
	}
	log.Logger.Info("Outputs terminated")

	for _, route := range ctx.inputRoutes {
		route.StopScheduler()
	}
	log.Logger.Info("Route schedulers stopped")

	log.Logger.Infof("ctx.quit %v\n", ctx.quit)

	if ctx.quit != nil {
		ctx.quit <- struct{}{}
	}

	log.Logger.Info("quit notified")

	if ctx.ticker != nil {
		ctx.stopTicker <- struct{}{}
		log.Logger.Info("stopTicker notified")
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

func (ctx *Router) addTemplate(template *data.Template) error {
	if err := ctx.initTemplate(template); err != nil {
		return err
	}

	ctx.databaseCfgCacheSource.Templates = append(ctx.databaseCfgCacheSource.Templates, *template)
	if err := ctx.saveCfgCacheSourceInPostgres(); err != nil {
		return err
	}
	return nil
}

func (ctx *Router) deleteTemplate(name string, removeFromRoutes bool) error {
	_, ok := ctx.templates[name]
	if !ok {
		return xerrors.Errorf("template %s is not found", name)
	}
	delete(ctx.templates, name)

	if removeFromRoutes {
		for _, route := range ctx.inputRoutes {
			if route.Template == name {
				route.Template = ""
			}
		}
	}

	removeTemplateFromCfgCacheSource(ctx.databaseCfgCacheSource, name)
	if err := ctx.saveCfgCacheSourceInPostgres(); err != nil {
		return err
	}
	return nil
}

func removeTemplateFromCfgCacheSource(outputs *data.TenantSettings, templateName string) {
	filtered := make([]data.Template, 0)
	for _, template := range outputs.Templates {
		if template.Name != templateName {
			filtered = append(filtered, template)
		}
	}
	outputs.Templates = filtered
}

func (ctx *Router) initTemplate(template *data.Template) error {
	log.Logger.Infof("Configuring template %s \n", template.Name)

	if template.LegacyScanRenderer != "" {
		inpteval, err := formatting.BuildLegacyScnEvaluator(template.LegacyScanRenderer)
		if err != nil {
			return err
		}
		ctx.templates[template.Name] = inpteval
		log.Logger.Infof("Configured with legacy renderer %s \n", template.LegacyScanRenderer)
	}

	if template.RegoPackage != "" {
		inpteval, err := regoservice.BuildBundledRegoEvaluator(template.RegoPackage)
		if err != nil {
			return err
		}
		ctx.templates[template.Name] = inpteval
		log.Logger.Infof("Configured with Rego package %s\n", template.RegoPackage)
	}
	if template.Url != "" {
		log.Logger.Infof("Configured with url: %s\n", template.Url)

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
	ctx.databaseCfgCacheSource.AquaServer = url
	if err := ctx.saveCfgCacheSourceInPostgres(); err != nil {
		log.Logger.Errorf("Can't save cfgSource Source: %v", err)
	}
}

func (ctx *Router) initTenantSettings(tenant *data.TenantSettings) error {
	ctx.mutexScan.Lock()
	defer ctx.mutexScan.Unlock()
	log.Logger.Infof("Loading alerts configuration file %s ....\n", ctx.cfgfile)

	ctx.setAquaServerUrl(tenant.AquaServer)

	postgresUrl := os.Getenv("POSTGRES_URL")
	pathToDb := os.Getenv("PATH_TO_DB")

	if err = dbservice.ConfigureDb(pathToDb, postgresUrl, tenant.Name); err != nil {
		return err
	}

	dbparam.DbSizeLimit = tenant.DBMaxSize

	actualDbTestInterval := tenant.DBTestInterval

	if tenant.DBTestInterval == 0 {
		actualDbTestInterval = 1
	}

	ctx.ticker = time.NewTicker(baseForTicker * time.Duration(actualDbTestInterval))
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
			log.Logger.Errorf("Can not initialize template %s: %v \n", t.Name, err)
		}
	}

	for _, settings := range tenant.Outputs {
		utils.Debug("%#v\n", anonymizeSettings(&settings))

		err := ctx.addOutput(&settings)

		if err != nil {
			log.Logger.Errorf("Can not initialize output %s: %v \n", settings.Name, err)
		} else {
			log.Logger.Infof("Output %s is configured", settings.Name)
		}

	}
	ctx.databaseCfgCacheSource = tenant
	return nil
}
func (ctx *Router) setInputCallbackFunc(routeName string, callback InputCallbackFunc) {
	inputCallBacks := ctx.inputCallBacks[routeName]
	inputCallBacks = append(inputCallBacks, callback)

	ctx.inputCallBacks[routeName] = inputCallBacks
}

func (ctx *Router) addRoute(r *routes.InputRoute) {
	ctx.inputRoutes[r.Name] = routes.ConfigureTimeouts(r)
	ctx.databaseCfgCacheSource.InputRoutes = append(ctx.databaseCfgCacheSource.InputRoutes, *r)
	if err := ctx.saveCfgCacheSourceInPostgres(); err != nil {
		log.Logger.Errorf("Can't save cfgSource Source: %v", err)
	}
}

func (ctx *Router) deleteRoute(name string) error {
	r, ok := ctx.inputRoutes[name]
	if !ok {
		return xerrors.Errorf("output %s is not found", name)
	}
	r.StopScheduler()
	delete(ctx.inputRoutes, name)
	delete(ctx.inputCallBacks, name)

	removeRouteFromCfgCacheSource(ctx.databaseCfgCacheSource, name)
	if err := ctx.saveCfgCacheSourceInPostgres(); err != nil {
		return err
	}

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

func removeRouteFromCfgCacheSource(outputs *data.TenantSettings, routeName string) {
	filtered := make([]routes.InputRoute, 0)
	for _, route := range outputs.InputRoutes {
		if route.Name != routeName {
			filtered = append(filtered, route)
		}
	}
	outputs.InputRoutes = filtered
}

func (ctx *Router) addOutput(settings *data.OutputSettings) error {
	if settings.Enable {
		plg, err := buildAndInitOtpt(settings, ctx.aquaServer)

		if err != nil {
			return err
		}

		ctx.outputs[settings.Name] = plg

	}

	ctx.databaseCfgCacheSource.Outputs = append(ctx.databaseCfgCacheSource.Outputs, *settings)
	if err := ctx.saveCfgCacheSourceInPostgres(); err != nil {
		return err
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
	removeOutputFromCfgCacheSource(ctx.databaseCfgCacheSource, outputName)
	if err := ctx.saveCfgCacheSourceInPostgres(); err != nil {
		return err
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

func removeOutputFromCfgCacheSource(outputs *data.TenantSettings, outputName string) {
	filtered := make([]data.OutputSettings, 0)
	for _, output := range outputs.Outputs {
		if output.Name != outputName {
			filtered = append(filtered, output)
		}
	}
	outputs.Outputs = filtered
}

func (ctx *Router) saveCfgCacheSourceInPostgres() error {
	cfg := ctx.databaseCfgCacheSource
	if postgresDb, ok := dbservice.Db.(*postgresdb.PostgresDb); ok {
		cfgFile, err := json.Marshal(cfg)
		if err != nil {
			return err
		}
		if err = postgresdb.UpdateCfgCacheSource(postgresDb, string(cfgFile)); err != nil {
			return err
		}
	}
	return nil
}

func (ctx *Router) loadCfgCacheSourceFromPostgres() (*data.TenantSettings, error) {
	cfg := &data.TenantSettings{}
	if postgresDb, ok := dbservice.Db.(*postgresdb.PostgresDb); ok {
		cfgFile, err := postgresdb.GetCfgCacheSource(postgresDb)
		if err != nil {
			return cfg, err
		}
		err = json.Unmarshal([]byte(cfgFile), &cfg)
		if err != nil {
			return cfg, err
		}
	}
	return cfg, nil
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
		log.Logger.Errorf("There isn't route %q", routeName)
		return
	}
	if len(r.Outputs) == 0 {
		log.Logger.Errorf("route %q has no outputs", routeName)
		return
	}

	if !getScanService().EvaluateRegoRule(r, in) {
		return
	}

	for _, outputName := range r.Outputs {
		pl, ok := ctx.outputs[outputName]
		if !ok {
			log.Logger.Errorf("route %q contains an output %q, which doesn't enable now.", routeName, outputName)
			continue
		}
		tmpl, ok := ctx.templates[r.Template]
		if !ok {
			log.Logger.Errorf("route %q contains reference to undefined or misconfigured template %q.",
				routeName, r.Template)
			continue
		}
		log.Logger.Infof("route %q is associated with template %q", routeName, r.Template)

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
		log.Logger.Errorf("failed to Init : %v", err)
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
