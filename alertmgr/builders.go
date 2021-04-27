package alertmgr

import (
	"github.com/aquasecurity/postee/plugins"
	"strings"
)

func buildSplunkPlugin(sourceSettings *PluginSettings) *plugins.SplunkPlugin {
	return &plugins.SplunkPlugin{
		Name:       sourceSettings.Name,
		Url:        sourceSettings.Url,
		Token:      sourceSettings.Token,
		EventLimit: sourceSettings.SizeLimit,
	}
}

func buildWebhookPlugin(sourceSettings *PluginSettings) *plugins.WebhookPlugin {
	return &plugins.WebhookPlugin{
		Name: sourceSettings.Name,
		Url:  sourceSettings.Url,
	}
}

func buildTeamsPlugin(sourceSettings *PluginSettings, aquaServer string) *plugins.TeamsPlugin {
	return &plugins.TeamsPlugin{
		Name:       sourceSettings.Name,
		AquaServer: aquaServer,
		Webhook:    sourceSettings.Url,
	}
}

func buildServiceNow(sourceSettings *PluginSettings) *plugins.ServiceNowPlugin {
	serviceNow := &plugins.ServiceNowPlugin{
		Name:     sourceSettings.Name,
		User:     sourceSettings.User,
		Password: sourceSettings.Password,
		Table:    sourceSettings.BoardName,
		Instance: sourceSettings.InstanceName,
	}
	if len(serviceNow.Table) == 0 {
		serviceNow.Table = ServiceNowTableDefault
	}
	return serviceNow
}

func buildSlackPlugin(sourceSettings *PluginSettings, aqua string) *plugins.SlackPlugin {
	return &plugins.SlackPlugin{
		Name:       sourceSettings.Name,
		AquaServer: aqua,
		Url:        sourceSettings.Url,
	}
}

func buildEmailPlugin(sourceSettings *PluginSettings) *plugins.EmailPlugin {
	return &plugins.EmailPlugin{
		Name:       sourceSettings.Name,
		User:       sourceSettings.User,
		Password:   sourceSettings.Password,
		Host:       sourceSettings.Host,
		Port:       sourceSettings.Port,
		Sender:     sourceSettings.Sender,
		Recipients: sourceSettings.Recipients,
		UseMX:      sourceSettings.UseMX,
	}
}

func buildJiraPlugin(sourceSettings *PluginSettings) *plugins.JiraAPI {
	jiraApi := &plugins.JiraAPI{
		Name:            sourceSettings.Name,
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
	return jiraApi
}
