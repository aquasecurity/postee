package router

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
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
	rego_templates "github.com/aquasecurity/postee/v2/rego-templates"
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
	outputs                sync.Map //map[string]outputs.Output
	outputsTemplate        sync.Map
	inputRoutes            sync.Map //map[string]*routes.InputRoute
	templates              sync.Map //map[string]data.Inpteval
	synchronous            bool
	inputCallBacks         map[string][]InputCallbackFunc
	databaseCfgCacheSource *data.TenantSettings
	callbackMu             sync.RWMutex
	lockEval               sync.Mutex
}

var (
	initCtx       sync.Once
	routerCtx     *Router
	baseForTicker = time.Hour

	requireAuthorization = map[string]bool{
		"servicenow": true,
	}
)

func Instance(loggers ...log.LoggerType) *Router {
	initCtx.Do(func() {
		if len(loggers) > 0 {
			if l := loggers[0]; l != nil {
				log.SetLogger(l)
			}
		}
		routerCtx = &Router{
			mutexScan:              sync.Mutex{},
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

	err = dbservice.ConfigureDb(pathToDb, postgresUrl, tenant.Name)
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

	err := ctx.initTenantSettings(tenant, synchronous)
	if err != nil {
		return err
	}

	if !ctx.synchronous {
		go ctx.listen()
	}

	return nil

}

func (ctx *Router) Terminate() {
	log.Logger.Debug("Terminating Router....")

	ctx.outputs.Range(func(_, value interface{}) bool {
		out, ok := value.(outputs.Output)
		if ok {
			err := out.Terminate()
			if err != nil {
				log.Logger.Errorf("failed to terminate output: %v", err)
			}
		}
		return true
	})

	log.Logger.Debug("Outputs terminated")

	ctx.inputRoutes.Range(func(_, value interface{}) bool {
		route, ok := value.(*routes.InputRoute)
		if ok {
			route.StopScheduler()
		}
		return true
	})

	log.Logger.Debug("Route schedulers stopped")

	log.Logger.Debugf("ctx.quit %v", ctx.quit)

	if ctx.quit != nil {
		ctx.quit <- struct{}{}
	}

	log.Logger.Debug("quit notified")

	if ctx.ticker != nil && ctx.stopTicker != nil {
		ctx.stopTicker <- struct{}{}
		log.Logger.Debug("stopTicker notified")
	}

	if dbservice.Db != nil {
		dbservice.Db.Close()
	}

	ctx.cleanInstance()
}

func (ctx *Router) cleanInstance() {
	ctx.outputsTemplate = sync.Map{}
	ctx.outputs = sync.Map{}
	ctx.inputRoutes = sync.Map{}
	ctx.templates = sync.Map{}

	ctx.callbackMu.Lock()
	ctx.inputCallBacks = map[string][]InputCallbackFunc{}
	ctx.callbackMu.Unlock()

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

	return nil
}

func (ctx *Router) deleteTemplate(name string, removeFromRoutes bool) error {
	_, ok := ctx.templates.LoadAndDelete(name)
	if !ok {
		return xerrors.Errorf("template %s is not found", name)
	}

	if removeFromRoutes {
		ctx.inputRoutes.Range(func(_, value interface{}) bool {
			route, ok := value.(*routes.InputRoute)
			if ok {
				if route.Template == name {
					route.Template = ""
				}
			}
			return true
		})
	}

	return nil
}

func (ctx *Router) initTemplate(template *data.Template) error {
	if template.LegacyScanRenderer != "" {
		inpteval, err := formatting.BuildLegacyScnEvaluator(template.LegacyScanRenderer)
		if err != nil {
			return err
		}
		ctx.templates.Store(template.Name, inpteval)
		log.Logger.Debugf("Configured template '%s' with legacy renderer %s", template.Name, template.LegacyScanRenderer)
	}

	if template.RegoPackage != "" {
		inpteval, err := regoservice.BuildBundledRegoEvaluator(template.RegoPackage)
		if err != nil {
			return err
		}
		ctx.templates.Store(template.Name, inpteval)
		log.Logger.Debugf("Configured template '%s' with Rego package %s", template.Name, template.RegoPackage)
	}
	if template.Url != "" {
		log.Logger.Debugf("Configured template '%s' with url: %s", template.Name, template.Url)

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

		ctx.templates.Store(template.Name, inpteval)
	}
	//body goes last to provide an option to keep body in config but not use it
	if template.Body != "" {
		inpteval, err := regoservice.BuildExternalRegoEvaluator("inline.rego", template.Body)
		if err != nil {
			return err
		}
		ctx.templates.Store(template.Name, inpteval)
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

func (ctx *Router) initTenantSettings(tenant *data.TenantSettings, synchronous bool) error {
	ctx.mutexScan.Lock()
	defer ctx.mutexScan.Unlock()
	log.Logger.Infof("Loading alerts configuration file %s ....", ctx.cfgfile)

	ctx.setAquaServerUrl(tenant.AquaServer)

	dbparam.DbSizeLimit = tenant.DBMaxSize

	actualDbTestInterval := tenant.DBTestInterval

	if tenant.DBTestInterval == 0 {
		actualDbTestInterval = 1
	}

	if !synchronous {
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
	}

	//----------------------------------------------------

	for i := range tenant.InputRoutes {
		ctx.addRoute(&tenant.InputRoutes[i])
	}
	for _, t := range tenant.Templates {
		err := ctx.initTemplate(&t)
		if err != nil {
			log.Logger.Errorf("Can not initialize template %s: %v", t.Name, err)
		}
	}

	for _, settings := range tenant.Outputs {
		log.Logger.Debugf("%#v", anonymizeSettings(&settings))

		err := ctx.addOutput(&settings)

		if err != nil {
			log.Logger.Errorf("Can not initialize output %s: %v", settings.Name, err)
		} else {
			log.Logger.Infof("Output %s is configured", settings.Name)
		}

	}
	ctx.databaseCfgCacheSource = tenant
	return nil
}
func (ctx *Router) setInputCallbackFunc(routeName string, callback InputCallbackFunc) {
	ctx.callbackMu.Lock()
	defer ctx.callbackMu.Unlock()
	inputCallBacks := ctx.inputCallBacks[routeName]
	inputCallBacks = append(inputCallBacks, callback)

	ctx.inputCallBacks[routeName] = inputCallBacks
}

func (ctx *Router) addRoute(r *routes.InputRoute) {
	log.Logger.Infof("Adding new route: %v", r.Name)
	ctx.inputRoutes.Store(r.Name, routes.ConfigureTimeouts(r))
}

func (ctx *Router) deleteCallback(name string) {
	ctx.callbackMu.Lock()
	defer ctx.callbackMu.Unlock()
	delete(ctx.inputCallBacks, name)
}

func (ctx *Router) deleteRoute(name string) error {
	val, ok := ctx.inputRoutes.LoadAndDelete(name)
	if !ok {
		return xerrors.Errorf("output %s is not found", name)
	}

	r, ok := val.(*routes.InputRoute)
	if ok {
		r.StopScheduler()
	}
	ctx.deleteCallback(name)
	return nil
}

func (ctx *Router) listRoutes() []routes.InputRoute {
	list := make([]routes.InputRoute, 0)
	ctx.inputRoutes.Range(func(_, value interface{}) bool {
		r, ok := value.(*routes.InputRoute)
		if ok {
			list = append(list, routes.InputRoute{
				Name:    r.Name,
				Input:   r.Input,
				Outputs: data.CopyStringArray(r.Outputs),
				Plugins: routes.Plugins{
					AggregateMessageNumber:      r.Plugins.AggregateMessageNumber,
					AggregateMessageTimeout:     r.Plugins.AggregateMessageTimeout,
					AggregateTimeoutSeconds:     r.Plugins.AggregateTimeoutSeconds,
					UniqueMessageProps:          r.Plugins.UniqueMessageProps,
					UniqueMessageTimeout:        r.Plugins.UniqueMessageTimeout,
					UniqueMessageTimeoutSeconds: r.Plugins.UniqueMessageTimeoutSeconds,
				},
				Template: r.Template,
			})
		}

		return true
	})

	return list
}

func (ctx *Router) addOutput(settings *data.OutputSettings) error {
	if settings.Enable {
		plg, err := buildAndInitOtpt(settings, ctx.aquaServer)
		if err != nil {
			return err
		}

		ctx.outputs.Store(settings.Name, plg)

		if settings.Template != "" {
			ctx.outputsTemplate.Store(settings.Name, settings.Template)
		}
	}

	return nil
}
func (ctx *Router) deleteOutput(outputName string, removeFromRoutes bool) error {
	val, ok := ctx.outputs.LoadAndDelete(outputName)
	if !ok {
		return xerrors.Errorf("output %s is not found", outputName)
	}

	output, ok := val.(outputs.Output)
	if ok {
		if err := output.Terminate(); err != nil {
			return err
		}
	}

	ctx.outputsTemplate.Delete(outputName)

	if removeFromRoutes {
		ctx.inputRoutes.Range(func(_, value interface{}) bool {
			route, ok := value.(*routes.InputRoute)
			if ok {
				removeOutputFromRoute(route, outputName)
			}
			return true
		})
	}

	return nil
}
func (ctx *Router) listOutputs() []data.OutputSettings {
	r := make([]data.OutputSettings, 0)
	ctx.outputs.Range(func(_, value interface{}) bool {
		output, ok := value.(outputs.Output)
		if ok {
			r = append(r, *output.CloneSettings())
		}
		return true
	})

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
	HandleSendToOutput(in map[string]interface{}, output outputs.Output, route *routes.InputRoute, inpteval data.Inpteval, AquaServer *string) (data.OutputResponse, error)
	EvaluateRegoRule(r *routes.InputRoute, input map[string]interface{}) bool
	GetMessageUniqueId(in map[string]interface{}, props []string) string
}

var getScanService = func() service {
	serv := &msgservice.MsgService{}
	return serv
}
var getHttpClient = func() *http.Client {
	return http.DefaultClient
}

func (ctx *Router) HandleRoute(routeName string, in []byte) {
	inMsg, err := parseInputMessage(in)
	if err != nil {
		return
	}

	ctx.handleRouteMsgParsed(routeName, inMsg)
}

func (ctx *Router) getCallbacks(name string) []InputCallbackFunc {
	ctx.callbackMu.RLock()
	defer ctx.callbackMu.RUnlock()
	return ctx.inputCallBacks[name]
}

func (ctx *Router) handleRouteMsgParsed(routeName string, inMsg map[string]interface{}) {
	val, ok := ctx.inputRoutes.Load(routeName)
	if !ok {
		log.Logger.Errorf("There isn't route %q", routeName)
		return
	}
	r, ok := val.(*routes.InputRoute)
	if !ok || r == nil {
		log.Logger.Errorf("route %q is nil", routeName)
		return
	}

	if len(r.Outputs) == 0 {
		log.Logger.Errorf("route %q has no outputs", routeName)
		return
	}

	if !ctx.isRouteMatch(r, inMsg) {
		return
	}

	ctx.publishToOutput(inMsg, r)
}

func parseInputMessage(in []byte) (msg map[string]interface{}, err error) {
	if err := json.Unmarshal(in, &msg); err != nil {
		log.PrnInputError("json.Unmarshal error for %q: %v", in, err)
	}

	return msg, err
}

func (ctx *Router) publishToOutput(msg map[string]interface{}, r *routes.InputRoute) {
	for _, outputName := range r.Outputs {
		pl, ok := ctx.outputs.Load(outputName)
		if !ok {
			log.Logger.Debugf("Route %q contains reference to not enabled output %q.", r.Name, outputName)
			continue
		}

		templateName := r.Template
		val, ok := ctx.outputsTemplate.Load(outputName)
		if ok {
			if name, ok := val.(string); ok && name != "" {
				templateName = name
			}
		}

		name, ok := r.OverrideTemplate[outputName]
		if ok && name != "" {
			templateName = name
		}

		tmpl, ok := ctx.templates.Load(templateName)
		if !ok {
			log.Logger.Errorf("Route %q contains reference to undefined or misconfigured template %q.",
				r.Name, templateName)
			continue
		}
		log.Logger.Infof("route %q is associated with output %q and template %q", r.Name, outputName, templateName)

		if ctx.synchronous {
			getScanService().MsgHandling(msg, pl.(outputs.Output), r, tmpl.(data.Inpteval), &ctx.aquaServer)
		} else {
			go getScanService().MsgHandling(msg, pl.(outputs.Output), r, tmpl.(data.Inpteval), &ctx.aquaServer)
		}
	}
}

func (ctx *Router) publish(msg map[string]interface{}, r *routes.InputRoute) map[string]data.OutputResponse {
	ticketIds := make(map[string]data.OutputResponse)
	for _, outputName := range r.Outputs {
		pl, ok := ctx.outputs.Load(outputName)
		if !ok {
			log.Logger.Errorf("Route %q contains reference to not enabled output %q.", r.Name, outputName)
			continue
		}

		templateName := r.Template
		val, ok := ctx.outputsTemplate.Load(outputName)
		if ok {
			if name, ok := val.(string); ok && name != "" {
				templateName = name
			}
		}

		name, ok := r.OverrideTemplate[outputName]
		if ok && name != "" {
			templateName = name
		}

		tmpl, ok := ctx.templates.Load(templateName)
		if !ok {
			log.Logger.Errorf("Route %q (output: %s) contains reference to undefined or misconfigured template %q.",
				r.Name, outputName, templateName)
			continue
		}
		log.Logger.Debugf("route %q is associated with output %q and template %q", r.Name, outputName, templateName)

		id, err := getScanService().HandleSendToOutput(msg, pl.(outputs.Output), r, tmpl.(data.Inpteval), &ctx.aquaServer)
		if err != nil {
			log.Logger.Errorf("route %q failed sending message to output: %s", r.Name, outputName)
			continue
		}

		if id.Key != "" {
			ticketIds[pl.(outputs.Output).GetType()] = id
		}
	}
	return ticketIds
}

func (ctx *Router) handle(in []byte) {
	ctx.inputRoutes.Range(func(key, _ interface{}) bool {
		routeName, ok := key.(string)
		if ok {
			ctx.HandleRoute(routeName, in)
		}
		return true
	})
}

func (ctx *Router) handleMsg(msg map[string]interface{}) {
	ctx.inputRoutes.Range(func(key, _ interface{}) bool {
		routeName, ok := key.(string)
		if ok {
			ctx.handleRouteMsgParsed(routeName, msg)
		}
		return true
	})
}

func (ctx *Router) Evaluate(in []byte) []string {
	inMsg, err := parseInputMessage(in)
	if err != nil {
		return []string{}
	}

	return ctx.evaluateMsg(inMsg)
}

func (ctx *Router) isRouteMatch(route *routes.InputRoute, inMsg map[string]interface{}) bool {
	inputCallbacks := ctx.getCallbacks(route.Name)
	for _, callback := range inputCallbacks {
		if !callback(inMsg) {
			return false
		}
	}

	return getScanService().EvaluateRegoRule(route, inMsg)
}

func (ctx *Router) LockEval() {
	ctx.lockEval.Lock()
}

func (ctx *Router) UnlockEval() {
	ctx.lockEval.Unlock()
}

func (ctx *Router) evaluateMsg(inMsg map[string]interface{}) []string {
	ctx.lockEval.Lock()
	defer ctx.lockEval.Unlock()
	routesNames := []string{}
	ctx.inputRoutes.Range(func(_, value interface{}) bool {
		r, ok := value.(*routes.InputRoute)
		if ok {
			if ctx.isRouteMatch(r, inMsg) {
				routesNames = append(routesNames, r.Name)
			}
		}
		return true
	})

	return routesNames
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
		if len(settings.Token) == 0 {
			if len(settings.User) == 0 || len(settings.Password) == 0 {
				return nil, xerrors.Errorf("user or password for %q is empty", settings.Name)
			}
		}
	}

	log.Logger.Debugf("Building Output %q: %q", settings.Type, settings.Name)

	var plg outputs.Output
	var err error

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
	case "exec":
		plg = buildExecOutput(settings)
	case "http":
		plg, err = buildHTTPOutput(settings)
		if err != nil {
			return nil, err
		}
	default:
		return nil, xerrors.Errorf("output %s has undefined or empty type: %q", settings.Name, settings.Type)
	}

	err = plg.Init()
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

func (ctx *Router) GetMessageUniqueId(b []byte, routeName string) (string, error) {
	msg, err := parseInputMessage(b)
	if err != nil {
		return "", xerrors.Errorf("error when trying to parse input message: %s", err.Error())
	}

	return ctx.getMessageUniqueId(msg, routeName)
}

func (ctx *Router) getMessageUniqueId(msg map[string]interface{}, routeName string) (string, error) {
	route, exists := ctx.inputRoutes.Load(routeName)
	if !exists {
		return "", xerrors.Errorf("route %ss was not found in the current router", routeName)
	}

	return getScanService().GetMessageUniqueId(msg, route.(*routes.InputRoute).Plugins.UniqueMessageProps), nil
}

func (ctx *Router) sendByRoute(in []byte, routeName string) (ticketIds map[string]data.OutputResponse, err error) {
	inMsg, err := parseInputMessage(in)
	if err != nil {
		return ticketIds, xerrors.Errorf("failed parsing input message: %s", err.Error())
	}

	return ctx.sendMsgByRoute(inMsg, routeName)
}

func (ctx *Router) sendMsgByRoute(inMsg map[string]interface{}, routeName string) (ticketIds map[string]data.OutputResponse, err error) {
	val, exists := ctx.inputRoutes.Load(routeName)
	if !exists {
		return ticketIds, xerrors.Errorf("route %s does not exists", routeName)
	}

	route, ok := val.(*routes.InputRoute)
	if ok {
		if len(route.Outputs) == 0 {
			log.Logger.Warnf("route %q has no outputs", routeName)
			return ticketIds, nil
		}

		ticketIds = ctx.publish(inMsg, route)

	}

	return ticketIds, nil
}

func (ctx *Router) embedTemplates() error {
	templates := rego_templates.GetAllTemplates()
	for _, t := range templates {
		err := ctx.addTemplate(&t)
		if err != nil {
			return err
		}
	}
	return nil
}
