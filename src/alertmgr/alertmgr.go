package alertmgr

import (
	"github.com/ghodss/yaml"
	"io/ioutil"
	"log"
	"sync"
	"utils"
)

type Plugin interface {
	Init() error
	Send(data string) error
	Terminate() error
}

type PluginSettings struct {
	Name        string `json:"name"`
	Enable      bool   `json:"enable"`
	Url         string `json:"url"`
	User        string `json:"user"`
	Password    string `json:"password"`
	Board       string `json:"board"`
	Assignee    string `json:"assignee"`
	Ticket      string `json:"ticket"`
	Description string `json:"description"`
	Summary     string `json:"summary"`
}

type AlertMgr struct {
	mutex   sync.Mutex
	quit    chan struct{}
	queue   chan string
	cfgfile string
	plugins map[string]Plugin
}

var initCtx sync.Once
var alertmgrCtx *AlertMgr

func Instance() *AlertMgr {
	initCtx.Do(func() {
		alertmgrCtx = &AlertMgr{
			mutex:   sync.Mutex{},
			quit:    make(chan struct{}),
			queue:   make(chan string, 1000),
			plugins: make(map[string]Plugin),
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
	for _, settings := range pluginSettings {
		utils.Debug("%#v\n", settings)
		if settings.Enable {
			utils.Debug("Starting Plugin %s\n", settings.Name)
			switch settings.Name {
			case "jira":
				plugin := NewJiraAPI(settings)
				plugin.Init()
				ctx.plugins["jira"] = plugin
			}
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
			for _, plugin := range ctx.plugins {
				if plugin != nil {
					go plugin.Send(data)
				}
			}
		}
	}
}
