package alertmgr

import (
	"io/ioutil"
	"log"
	"plugins"
	"scanservice"
	"settings"
	"strconv"
	"strings"
	"sync"

	"github.com/ghodss/yaml"
	"utils"
)

const (
	IssueTypeDefault = "Task"
	PriorityDefault = "High"
)

type PluginSettings struct {
	Name            string `json:"name"`
	Type            string `json:"type"`
	Enable          bool   `json:"enable"`
	Url             string `json:"url"`
	User            string `json:"user"`
	Password        string `json:"password"`
	TlsVerify       bool   `json:"tls_verify"`
	ProjectKey      string `json:"project_key,omitempty" structs:"project_key,omitempty"`
	IssueType       string `json:"issuetype" structs:"issuetype"`
	BoardName       string `json:"board,omitempty" structs:"board,omitempty"`
	Priority        string `json:"priority,omitempty"`
	Assignee        string `json:"assignee,omitempty"`
	Description     string
	Summary         string            `json:"summary,omitempty"`
	FixVersions     []string          `json:"fixVersions,omitempty"`
	AffectsVersions []string          `json:"affectsVersions,omitempty"`
	Labels          []string          `json:"labels,omitempty"`
	Sprint          string            `json:"sprint,omitempty"`
	Unknowns        map[string]string `json:"unknowns" structs:"unknowns,omitempty"`

	Host       string   `json:"host"`
	Port       string   `json:"port"`
	Recipients []string `json:"recipients"`
	Sender     string   `json:"sender"`

	Token     string   `json:"token"`

	PolicyMinVulnerability string   `json:"Policy-Min-Vulnerability"`
	PolicyRegistry         []string `json:"Policy-Registry"`
	PolicyImageName        []string `json:"Policy-Image-Name"`
	PolicyNonCompliant     bool     `json:"Policy-Non-Compliant"`

	IgnoreRegistry  []string `json:"Ignore-Registry"`
	IgnoreImageName []string `json:"Ignore-Image-Name"`

	AggregateIssuesNumber  int    `json:"Aggregate-Issues-Number"`
	AggregateIssuesTimeout string `json:"Aggregate-Issues-Timeout"`
	PolicyOnlyFixAvailable bool `json:"Policy-Only-Fix-Available"`
}

type AlertMgr struct {
	mutex   sync.Mutex
	quit    chan struct{}
	queue   chan string
	cfgfile string
	plugins map[string]plugins.Plugin
}

var initCtx sync.Once
var alertmgrCtx *AlertMgr

func buildSettings(sourceSettings *PluginSettings) *settings.Settings {
	var timeout int
	var err error

	times := map[string]int {
		"s":1,
		"m": 60,
		"h": 3600,
	}

	if len(sourceSettings.AggregateIssuesTimeout) > 0 {
		wasConvert := false
		for suffix, k := range times {
			if strings.HasSuffix(strings.ToLower(sourceSettings.AggregateIssuesTimeout), suffix) {
				timeout, err = strconv.Atoi(strings.TrimSuffix(sourceSettings.AggregateIssuesTimeout, suffix))
				timeout *= k
				wasConvert = true
				break
			}
		}
		if !wasConvert {
			timeout, err = strconv.Atoi(sourceSettings.AggregateIssuesTimeout)
		}
		if err != nil {
			log.Printf("%q settings: Can't convert 'AggregateIssuesTimeout'(%q) to seconds.",
				sourceSettings.Name, sourceSettings.AggregateIssuesTimeout)
		}
	}
	return &settings.Settings{
		PluginName:              sourceSettings.Name,
		PolicyMinVulnerability:  sourceSettings.PolicyMinVulnerability,
		PolicyRegistry:          sourceSettings.PolicyRegistry,
		PolicyImageName:         sourceSettings.PolicyImageName,
		PolicyNonCompliant:      sourceSettings.PolicyNonCompliant,
		IgnoreRegistry:          sourceSettings.IgnoreRegistry,
		IgnoreImageName:         sourceSettings.IgnoreImageName,
		AggregateIssuesNumber:   sourceSettings.AggregateIssuesNumber,
		AggregateTimeoutSeconds: timeout,
		PolicyOnlyFixAvailable:	 sourceSettings.PolicyOnlyFixAvailable,
	}
}

func buildTeamsPlugin(sourceSettings *PluginSettings) *plugins.TeamsPlugin  {
	teams := &plugins.TeamsPlugin{
		Webhook: sourceSettings.Url,
	}
	teams.TeamsSettings = buildSettings(sourceSettings)
	return teams
}

func buildSlackPlugin(sourceSettings *PluginSettings) *plugins.SlackPlugin {
	slack := &plugins.SlackPlugin{}
	slack.Url = sourceSettings.Url
	slack.SlackSettings = buildSettings(sourceSettings)
	return slack
}

func buildEmailPlugin(sourceSettings *PluginSettings) *plugins.EmailPlugin {
	em := &plugins.EmailPlugin{
		User:          sourceSettings.User,
		Password:      sourceSettings.Password,
		Host:          sourceSettings.Host,
		Port:          sourceSettings.Port,
		Sender:        sourceSettings.Sender,
		Recipients:    sourceSettings.Recipients,
	}
	em.EmailSettings = buildSettings(sourceSettings)
	return em
}

func buildJiraPlugin(sourceSettings *PluginSettings) *plugins.JiraAPI {
	jiraApi := &plugins.JiraAPI{
		Url:             sourceSettings.Url,
		User:            sourceSettings.User,
		Password:        sourceSettings.Password,
		TlsVerify:       sourceSettings.TlsVerify,
		Issuetype:       sourceSettings.IssueType,
		ProjectKey:      sourceSettings.ProjectKey,
		Priority:        sourceSettings.Priority,
		Assignee:        sourceSettings.Assignee,
		FixVersions:     sourceSettings.FixVersions,
		AffectsVersions: sourceSettings.AffectsVersions,
		Labels:          sourceSettings.Labels,
		Unknowns:        sourceSettings.Unknowns,
		SprintName:      sourceSettings.Sprint,
		SprintId:        -1,
		BoardName:       sourceSettings.BoardName,
	}
	if jiraApi.Issuetype == "" {
		jiraApi.Issuetype = IssueTypeDefault
	}

	if jiraApi.Priority == "" {
		jiraApi.Priority = PriorityDefault
	}

	if jiraApi.Assignee == "" {
		jiraApi.Assignee = jiraApi.User
	}
	jiraApi.JiraSettings = buildSettings(sourceSettings)
	return jiraApi
}

func Instance() *AlertMgr {
	initCtx.Do(func() {
		alertmgrCtx = &AlertMgr{
			mutex:   sync.Mutex{},
			quit:    make(chan struct{}),
			queue:   make(chan string, 1000),
			plugins: make(map[string]plugins.Plugin),
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
			settings.User = utils.GetEnvironmentVarOrPlain(settings.User)
			if len(settings.User) == 0  && settings.Type != "slack" && settings.Type != "teams" {
				log.Printf("User for %q is empty", settings.Name)
				continue
			}
			settings.Password = utils.GetEnvironmentVarOrPlain(settings.Password)
			if len(settings.Password) == 0 && settings.Type != "slack" && settings.Type != "teams" {
				log.Printf("Password for %q is empty", settings.Name)
				continue
			}
			utils.Debug("Starting Plugin %q: %q\n", settings.Type, settings.Name)
			switch settings.Type {
			case "jira":
				plugin := buildJiraPlugin(&settings)
				plugin.Init()
				ctx.plugins[settings.Name] = plugin
			case "email":
				plugin := buildEmailPlugin(&settings)
				plugin.Init()
				ctx.plugins[settings.Name] = plugin
			case "slack":
				ctx.plugins[settings.Name] = buildSlackPlugin(&settings)
				ctx.plugins[settings.Name].Init()
			case "teams":
				ctx.plugins[settings.Name] = buildTeamsPlugin(&settings)
				ctx.plugins[settings.Name].Init()
			default:
				log.Printf("Plugin type %q is undefined or empty. Plugin name is %q.",
					settings.Type, settings.Name)
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
			service := new(scanservice.ScanService)
			go service.ResultHandling(data, ctx.plugins)
		}
	}
}
