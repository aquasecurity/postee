package router

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/outputs"
)

func buildStdoutOutput(sourceSettings *data.OutputSettings) *outputs.StdoutOutput {
	return &outputs.StdoutOutput{Name: sourceSettings.Name}
}

func buildSplunkOutput(sourceSettings *data.OutputSettings) *outputs.SplunkOutput {
	return &outputs.SplunkOutput{
		Name:       sourceSettings.Name,
		Url:        sourceSettings.Url,
		Token:      sourceSettings.Token,
		EventLimit: sourceSettings.SizeLimit,
	}
}

func buildWebhookOutput(sourceSettings *data.OutputSettings) *outputs.WebhookOutput {
	return &outputs.WebhookOutput{
		Name: sourceSettings.Name,
		Url:  sourceSettings.Url,
	}
}

func buildTeamsOutput(sourceSettings *data.OutputSettings, aquaServer string) *outputs.TeamsOutput {
	return &outputs.TeamsOutput{
		Name:       sourceSettings.Name,
		AquaServer: aquaServer,
		Webhook:    sourceSettings.Url,
	}
}

func buildServiceNow(sourceSettings *data.OutputSettings) *outputs.ServiceNowOutput {
	serviceNow := &outputs.ServiceNowOutput{
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

func buildSlackOutput(sourceSettings *data.OutputSettings, aqua string) *outputs.SlackOutput {
	return &outputs.SlackOutput{
		Name:       sourceSettings.Name,
		AquaServer: aqua,
		Url:        sourceSettings.Url,
	}
}

func buildEmailOutput(sourceSettings *data.OutputSettings) *outputs.EmailOutput {
	return &outputs.EmailOutput{
		Name:           sourceSettings.Name,
		User:           sourceSettings.User,
		Password:       sourceSettings.Password,
		Host:           sourceSettings.Host,
		Port:           sourceSettings.Port,
		Sender:         sourceSettings.Sender,
		Recipients:     sourceSettings.Recipients,
		ClientHostName: sourceSettings.ClientHostName,
		UseMX:          sourceSettings.UseMX,
	}
}

func buildJiraOutput(sourceSettings *data.OutputSettings) *outputs.JiraAPI {
	jiraApi := &outputs.JiraAPI{
		Name:            sourceSettings.Name,
		Url:             sourceSettings.Url,
		User:            sourceSettings.User,
		Password:        sourceSettings.Password,
		Token:           sourceSettings.Token,
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
		Summary:         sourceSettings.Summary,
	}
	if jiraApi.Issuetype == "" {
		if strings.ToLower(sourceSettings.Language) == "fr" {
			jiraApi.Issuetype = FrenchIssueTypeDefault
		} else {
			jiraApi.Issuetype = IssueTypeDefault
		}
	}
	if jiraApi.Priority == "" {
		jiraApi.Priority = PriorityDefault
	}
	if len(jiraApi.Assignee) == 0 {
		jiraApi.Assignee = []string{jiraApi.User}
	}
	return jiraApi
}

func buildExecOutput(sourceSettings *data.OutputSettings) *outputs.ExecClient {
	return &outputs.ExecClient{
		Name:      sourceSettings.Name,
		Env:       sourceSettings.Env,
		InputFile: sourceSettings.InputFile,
	}
}

func buildHTTPOutput(sourceSettings *data.OutputSettings) (*outputs.HTTPClient, error) {
	if len(sourceSettings.Method) <= 0 {
		return nil, fmt.Errorf("http action requires a method to be specified")
	}

	var duration time.Duration
	if len(sourceSettings.Timeout) > 0 {
		var err error
		duration, err = time.ParseDuration(sourceSettings.Timeout)
		if err != nil {
			return nil, fmt.Errorf("invalid duration specified: %w", err)
		}
	} else {
		duration = time.Second * 5
	}

	reqUrl, err := url.Parse(sourceSettings.Url)
	if err != nil {
		return nil, fmt.Errorf("error building HTTP url: %w", err)
	}

	var body []byte
	if len(sourceSettings.BodyFile) > 0 {
		var err error
		body, err = ioutil.ReadFile(sourceSettings.BodyFile)
		if err != nil {
			return nil, fmt.Errorf("http action unable to specified body-file: %s, err: %w", sourceSettings.BodyFile, err)
		}
	}

	return &outputs.HTTPClient{
		Name:    sourceSettings.Name,
		Client:  http.Client{Timeout: duration},
		URL:     reqUrl,
		Method:  strings.ToUpper(sourceSettings.Method),
		Body:    string(body),
		Headers: sourceSettings.Headers,
	}, nil
}
