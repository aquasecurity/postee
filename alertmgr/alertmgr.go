package alertmgr

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aquasecurity/postee/dbservice"
	"github.com/aquasecurity/postee/plugins"
	"github.com/aquasecurity/postee/scanservice"
	"github.com/aquasecurity/postee/settings"

	"github.com/aquasecurity/postee/utils"
	"github.com/ghodss/yaml"
)

const (
	IssueTypeDefault = "Task"
	PriorityDefault  = "High"

	ServiceNowTableDefault = "incident"
)

type PluginSettings struct {
	Name            string            `json:"name"`
	Type            string            `json:"type"`
	Enable          bool              `json:"enable,omitempty"`
	Url             string            `json:"url,omitempty"`
	User            string            `json:"user,omitempty"`
	Password        string            `json:"password,omitempty"`
	TlsVerify       bool              `json:"tls_verify,omitempty"`
	ProjectKey      string            `json:"project_key,omitempty" structs:"project_key,omitempty"`
	IssueType       string            `json:"issuetype,omitempty" structs:"issuetype"`
	BoardName       string            `json:"board,omitempty" structs:"board,omitempty"`
	Priority        string            `json:"priority,omitempty"`
	Assignee        []string          `json:"assignee,omitempty"`
	Description     string            `json:"-"`
	Summary         string            `json:"summary,omitempty"`
	FixVersions     []string          `json:"fixVersions,omitempty"`
	AffectsVersions []string          `json:"affectsVersions,omitempty"`
	Labels          []string          `json:"labels,omitempty"`
	Sprint          string            `json:"sprint,omitempty"`
	Unknowns        map[string]string `json:"unknowns,omitempty" structs:"unknowns,omitempty"`

	Host       string   `json:"host,omitempty"`
	Port       string   `json:"port,omitempty"`
	Recipients []string `json:"recipients,omitempty"`
	Sender     string   `json:"sender,omitempty"`
	Token      string   `json:"token,omitempty"`
	UseMX      bool     `json:"useMX,omitempty"`

	PolicyMinVulnerability string   `json:"Policy-Min-Vulnerability,omitempty"`
	PolicyRegistry         []string `json:"Policy-Registry,omitempty"`
	PolicyImageName        []string `json:"Policy-Image-Name,omitempty"`
	PolicyNonCompliant     bool     `json:"Policy-Non-Compliant,omitempty"`
	PolicyShowAll          bool     `json:"Policy-Show-All,omitempty"`

	IgnoreRegistry  []string `json:"Ignore-Registry,omitempty"`
	IgnoreImageName []string `json:"Ignore-Image-Name,omitempty"`

	AggregateIssuesNumber  int    `json:"Aggregate-Issues-Number,omitempty"`
	AggregateIssuesTimeout string `json:"Aggregate-Issues-Timeout,omitempty"`
	InstanceName           string `json:"instance,omitempty"`
	PolicyOnlyFixAvailable bool   `json:"Policy-Only-Fix-Available,omitempty"`

	PolicyOPA []string `json:"Policy-OPA,omitempty"`

	AquaServer      string `json:"AquaServer,omitempty"`
	DBMaxSize       int    `json:"Max_DB_Size,omitempty"`
	DBRemoveOldData int    `json:"Delete_Old_Data,omitempty"`
	DBTestInterval  int    `json:"DbVerifyInterval,omitempty"`

	SizeLimit int `json:"SizeLimit,omitempty"`
}

type AlertMgr struct {
	mutex      sync.Mutex
	quit       chan struct{}
	queue      chan string
	ticker     *time.Ticker
	stopTicker chan struct{}
	cfgfile    string
	plugins    map[string]plugins.Plugin
}

var initCtx sync.Once
var alertmgrCtx *AlertMgr
var aquaServer string
var baseForTicker = time.Hour

var osStat = os.Stat

var ignoreAuthorization map[string]bool = map[string]bool{
	"slack":   true,
	"teams":   true,
	"webhook": true,
	"email":   true,
	"splunk":  true,
}

func buildSettings(sourceSettings *PluginSettings) *settings.Settings {
	var timeout int
	var err error

	times := map[string]int{
		"s": 1,
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
	opaPolicy := []string{}
	if len(sourceSettings.PolicyOPA) > 0 {
		for _, policyFile := range sourceSettings.PolicyOPA {
			if _, err := osStat(policyFile); err != nil {
				if os.IsNotExist(err) {
					log.Printf("Policy file %q doesn't exist.", policyFile)
				} else {
					log.Printf("There is a problem with %q polycy: %v", policyFile, err)
				}
				continue
			}
			opaPolicy = append(opaPolicy, policyFile)
		}
	}

	return &settings.Settings{
		PluginName:              sourceSettings.Name,
		PolicyMinVulnerability:  sourceSettings.PolicyMinVulnerability,
		PolicyRegistry:          sourceSettings.PolicyRegistry,
		PolicyImageName:         sourceSettings.PolicyImageName,
		PolicyShowAll:           sourceSettings.PolicyShowAll,
		PolicyNonCompliant:      sourceSettings.PolicyNonCompliant,
		IgnoreRegistry:          sourceSettings.IgnoreRegistry,
		IgnoreImageName:         sourceSettings.IgnoreImageName,
		AggregateIssuesNumber:   sourceSettings.AggregateIssuesNumber,
		AggregateTimeoutSeconds: timeout,
		PolicyOnlyFixAvailable:  sourceSettings.PolicyOnlyFixAvailable,
		AquaServer:              aquaServer,
		PolicyOPA:               opaPolicy,
	}
}

func buildSplunkPlugin(sourceSettings *PluginSettings) *plugins.SplunkPlugin {
	return &plugins.SplunkPlugin{
		Url:            sourceSettings.Url,
		Token:          sourceSettings.Token,
		SplunkSettings: buildSettings(sourceSettings),
		EventLimit:     sourceSettings.SizeLimit,
	}
}

func buildWebhookPlugin(sourceSettings *PluginSettings) *plugins.WebhookPlugin {
	return &plugins.WebhookPlugin{
		Url:             sourceSettings.Url,
		WebhookSettings: buildSettings(sourceSettings),
	}
}

func buildTeamsPlugin(sourceSettings *PluginSettings) *plugins.TeamsPlugin {
	teams := &plugins.TeamsPlugin{
		Webhook: sourceSettings.Url,
	}
	teams.TeamsSettings = buildSettings(sourceSettings)
	return teams
}

func buildServiceNow(sourceSettings *PluginSettings) *plugins.ServiceNowPlugin {
	serviceNow := &plugins.ServiceNowPlugin{
		User:     sourceSettings.User,
		Password: sourceSettings.Password,
		Table:    sourceSettings.BoardName,
		Instance: sourceSettings.InstanceName,
	}
	serviceNow.ServiceNowSettings = buildSettings(sourceSettings)

	if len(serviceNow.Table) == 0 {
		serviceNow.Table = ServiceNowTableDefault
	}

	return serviceNow
}

func buildSlackPlugin(sourceSettings *PluginSettings) *plugins.SlackPlugin {
	slack := &plugins.SlackPlugin{}
	slack.Url = sourceSettings.Url
	slack.SlackSettings = buildSettings(sourceSettings)
	return slack
}

func buildEmailPlugin(sourceSettings *PluginSettings) *plugins.EmailPlugin {
	em := &plugins.EmailPlugin{
		User:       sourceSettings.User,
		Password:   sourceSettings.Password,
		Host:       sourceSettings.Host,
		Port:       sourceSettings.Port,
		Sender:     sourceSettings.Sender,
		Recipients: sourceSettings.Recipients,
		UseMX:      sourceSettings.UseMX,
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
		ProjectKey:      strings.ToUpper(sourceSettings.ProjectKey),
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

	if len(jiraApi.Assignee) == 0 {
		jiraApi.Assignee = []string{jiraApi.User}
	}
	jiraApi.JiraSettings = buildSettings(sourceSettings)
	return jiraApi
}

func Instance() *AlertMgr {
	initCtx.Do(func() {
		alertmgrCtx = &AlertMgr{
			mutex:      sync.Mutex{},
			quit:       make(chan struct{}),
			queue:      make(chan string, 1000),
			plugins:    make(map[string]plugins.Plugin),
			stopTicker: make(chan struct{}),
		}
	})
	return alertmgrCtx
}

func (ctx *AlertMgr) ReloadConfig() {
	ctx.Terminate()
	ctx.Start(ctx.cfgfile)
}

func (ctx *AlertMgr) Start(cfgfile string) {
	log.Printf("Starting AlertMgr....")
	ctx.cfgfile = cfgfile
	ctx.plugins = map[string]plugins.Plugin{}
	ctx.load()
	go ctx.listen()
}

func (ctx *AlertMgr) Terminate() {
	log.Printf("Terminating AlertMgr....")
	ctx.quit <- struct{}{}
	ctx.stopTicker <- struct{}{}
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
		if settings.Type == "common" {
			if len(settings.AquaServer) > 0 {
				var slash string
				if !strings.HasSuffix(settings.AquaServer, "/") {
					slash = "/"
				}
				aquaServer = fmt.Sprintf("%s%s#/images/", settings.AquaServer, slash)
			}
			dbservice.DbSizeLimit = settings.DBMaxSize
			dbservice.DbDueDate = settings.DBRemoveOldData

			if settings.DBTestInterval == 0 {
				settings.DBTestInterval = 1
			}

			if dbservice.DbSizeLimit != 0 || dbservice.DbDueDate != 0 {
				ctx.ticker = time.NewTicker(baseForTicker * time.Duration(settings.DBTestInterval))
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
			continue
		}

		if settings.Enable {
			plg := BuildAndInitPlg(&settings)
			if plg != nil {
				ctx.plugins[settings.Name] = plg
			}
		}
	}
	return nil
}
func BuildAndInitPlg(settings *PluginSettings) plugins.Plugin {
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
		plg = buildSlackPlugin(settings)
	case "teams":
		plg = buildTeamsPlugin(settings)
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
			service := new(scanservice.ScanService)
			go service.ResultHandling(strings.ReplaceAll(data, "`", "'"), ctx.plugins)
		}
	}
}
