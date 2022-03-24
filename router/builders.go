package router

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aquasecurity/postee/v2/outputs"
)

func buildStdoutOutput(sourceSettings *OutputSettings) *outputs.StdoutOutput {
	return &outputs.StdoutOutput{Name: sourceSettings.Name}
}

func buildSplunkOutput(sourceSettings *OutputSettings) *outputs.SplunkOutput {
	return &outputs.SplunkOutput{
		Name:       sourceSettings.Name,
		Url:        sourceSettings.Url,
		Token:      sourceSettings.Token,
		EventLimit: sourceSettings.SizeLimit,
	}
}

func buildWebhookOutput(sourceSettings *OutputSettings) *outputs.WebhookOutput {
	return &outputs.WebhookOutput{
		Name:    sourceSettings.Name,
		Url:     sourceSettings.Url,
		Timeout: sourceSettings.Timeout,
	}
}

func buildTeamsOutput(sourceSettings *OutputSettings, aquaServer string) *outputs.TeamsOutput {
	return &outputs.TeamsOutput{
		Name:       sourceSettings.Name,
		AquaServer: aquaServer,
		Webhook:    sourceSettings.Url,
	}
}

func buildServiceNow(sourceSettings *OutputSettings) *outputs.ServiceNowOutput {
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

func buildSlackOutput(sourceSettings *OutputSettings, aqua string) *outputs.SlackOutput {
	return &outputs.SlackOutput{
		Name:       sourceSettings.Name,
		AquaServer: aqua,
		Url:        sourceSettings.Url,
	}
}

func buildEmailOutput(sourceSettings *OutputSettings) *outputs.EmailOutput {
	return &outputs.EmailOutput{
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

func buildJiraOutput(sourceSettings *OutputSettings) *outputs.JiraAPI {
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
		SprintId:        outputs.NotConfiguredSprintId,
		BoardName:       sourceSettings.BoardName,
	}

	if len(jiraApi.Assignee) == 0 {
		jiraApi.Assignee = []string{jiraApi.User}
	}
	return jiraApi
}

func buildExecOutput(sourceSettings *OutputSettings) (*outputs.ExecClient, error) {
	if len(sourceSettings.InputFile) <= 0 && len(sourceSettings.ExecScript) <= 0 {
		return nil, fmt.Errorf("exec action requires either input-file or exec-script to be set")
	}

	if len(sourceSettings.InputFile) > 0 && len(sourceSettings.ExecScript) > 0 {
		return nil, fmt.Errorf("exec action only takes either input-file or exec-script, not both")
	}

	ec := &outputs.ExecClient{
		Name: sourceSettings.Name,
		Env:  sourceSettings.Env,
	}

	if len(sourceSettings.InputFile) > 0 {
		ec.InputFile = sourceSettings.InputFile
	}

	if len(sourceSettings.ExecScript) > 0 {
		ec.ExecScript = sourceSettings.ExecScript
	}

	return ec, nil
}

func buildHTTPOutput(sourceSettings *OutputSettings) (*outputs.HTTPClient, error) {
	if len(sourceSettings.Method) <= 0 {
		return nil, fmt.Errorf("http action requires a method to be specified")
	}

	if len(sourceSettings.BodyFile) > 0 && len(sourceSettings.BodyContent) > 0 {
		return nil, fmt.Errorf("http action requires only supports body-file or body-content, not both")
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

	hc := &outputs.HTTPClient{
		Name:    sourceSettings.Name,
		Client:  http.Client{Timeout: duration},
		URL:     reqUrl,
		Method:  strings.ToUpper(sourceSettings.Method),
		Headers: sourceSettings.Headers,
	}

	if len(sourceSettings.BodyFile) > 0 {
		hc.BodyFile = sourceSettings.BodyFile
	}
	if len(sourceSettings.BodyContent) > 0 {
		hc.BodyContent = sourceSettings.BodyContent
	}

	return hc, nil
}

func buildKubernetesOutput(sourceSettings *OutputSettings) (*outputs.KubernetesClient, error) {
	if !outputs.IsK8s() {
		if sourceSettings.KubeConfigFile == "" {
			return nil, fmt.Errorf("kubernetes config file needs to be set in config yaml")
		}
	}

	if sourceSettings.KubeNamespace == "" {
		return nil, fmt.Errorf("kubernetes namespace needs to be set in config yaml")
	}

	return &outputs.KubernetesClient{
		Name:              sourceSettings.Name,
		KubeNamespace:     sourceSettings.KubeNamespace,
		KubeConfigFile:    sourceSettings.KubeConfigFile,
		KubeLabelSelector: sourceSettings.KubeLabelSelector,
		KubeActions:       sourceSettings.KubeActions,
	}, nil
}

func buildDockerOutput(sourceSettings *OutputSettings) (*outputs.DockerClient, error) {
	if len(sourceSettings.DockerImageName) < 0 {
		return nil, fmt.Errorf("docker action requires an image name")
	}

	return &outputs.DockerClient{
		Name:      sourceSettings.Name,
		ImageName: sourceSettings.DockerImageName,
		Cmd:       sourceSettings.DockerCmd,
		Volumes:   sourceSettings.DockerVolumes,
		Env:       sourceSettings.DockerEnv,
	}, nil
}
