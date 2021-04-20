package alertmgr

import (
	"github.com/aquasecurity/postee/plugins"
	"github.com/aquasecurity/postee/settings"
	"log"
	"os"
	"strconv"
	"strings"
)

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
