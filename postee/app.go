package postee

import (
	"log"

	"github.com/aquasecurity/postee/router"
	"github.com/aquasecurity/postee/routes"
	"github.com/aquasecurity/postee/webserver"
)

type App struct {
	// TODO add lock to pause msg handling while config reload
	config            *router.TenantSettings
	webserver         *webserver.WebServer
	msgRouter         *router.Router
	msgRouterProvider func(*router.Router) *router.Router
}

type AppConfigBuilder struct {
	cfgpath         string
	url             string
	tls             string
	firstErr        error
	MsgRouterConfig *router.TenantSettings
}

func NewConfigFromFile(cfgpath string, url string, tls string) *AppConfigBuilder {
	cb := &AppConfigBuilder{
		cfgpath: cfgpath,
		url:     url,
		tls:     tls,
	}
	var err error

	cb.MsgRouterConfig, err = Parsev2cfg(cfgpath)
	if err != nil {
		cb.firstErr = err
	}

	return cb
}

func New(url string, tls string) *AppConfigBuilder {
	return &AppConfigBuilder{
		url: url,
		tls: tls,
	}
}

func (cb *AppConfigBuilder) AquaServer(aquaServer string) *AppConfigBuilder {
	cb.MsgRouterConfig.AquaServer = aquaServer
	return cb
}
func (cb *AppConfigBuilder) DBMaxSize(dbMaxSize int) *AppConfigBuilder {
	cb.MsgRouterConfig.DBMaxSize = dbMaxSize
	return cb
}
func (cb *AppConfigBuilder) DBTestInterval(dbTestInterval int) *AppConfigBuilder {
	cb.MsgRouterConfig.DBTestInterval = dbTestInterval
	return cb
}
func (cb *AppConfigBuilder) DBRemoveOldData(dbRemoveOldData int) *AppConfigBuilder {
	cb.MsgRouterConfig.DBRemoveOldData = dbRemoveOldData
	return cb
}

func (cb *AppConfigBuilder) AddOutput(output *router.OutputSettings) *AppConfigBuilder {
	cb.MsgRouterConfig.Outputs = append(cb.MsgRouterConfig.Outputs, *output)
	return cb
}
func (cb *AppConfigBuilder) AddRoute(route *routes.InputRoute) *AppConfigBuilder {
	cb.MsgRouterConfig.InputRoutes = append(cb.MsgRouterConfig.InputRoutes, *route)
	return cb
}
func (cb *AppConfigBuilder) AddTemplate(template *router.Template) *AppConfigBuilder {
	cb.MsgRouterConfig.Templates = append(cb.MsgRouterConfig.Templates, *template)
	return cb
}

func (cb *AppConfigBuilder) Start() (*App, error) {
	/*
	* Config of running app can not be changed.
	* App should be terminated first and started with new config
	 */

	if cb.firstErr != nil {
		return nil, cb.firstErr //report error found on early stages
	}

	app := &App{
		config: cb.MsgRouterConfig,
	}

	//support for config reload from Postee UI
	if cb.cfgpath != "" {
		app.msgRouterProvider = func(existing *router.Router) *router.Router {
			config, err := Parsev2cfg(cb.cfgpath)

			if err != nil {
				log.Printf("Can't re-start message router %v", err)
			}

			existing.Terminate()
			return router.New(config)
		}
	}

	app.start(cb.url, cb.tls)

	return app, nil
}

func (app *App) start(url string, tls string) {
	app.msgRouter = router.New(app.config)

	app.webserver = webserver.New(app.msgRouter, app.msgRouterProvider)

	go app.webserver.Start(url, tls)
}

func (app *App) Terminate() {
	app.msgRouter.Terminate()
	app.webserver.Terminate()
}
