package router

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aquasecurity/postee/v2/actions"
)

func buildStdoutAction(sourceSettings *ActionSettings) *actions.StdoutAction {
	return &actions.StdoutAction{Name: sourceSettings.Name}
}

func buildSplunkAction(sourceSettings *ActionSettings) *actions.SplunkAction {
	return &actions.SplunkAction{
		Name:       sourceSettings.Name,
		Url:        sourceSettings.Url,
		Token:      sourceSettings.Token,
		EventLimit: sourceSettings.SizeLimit,
		TlsVerify:  sourceSettings.TlsVerify,
	}
}

func buildWebhookAction(sourceSettings *ActionSettings) *actions.WebhookAction {
	return &actions.WebhookAction{
		Name:    sourceSettings.Name,
		Url:     sourceSettings.Url,
		Timeout: sourceSettings.Timeout,
	}
}

func buildTeamsAction(sourceSettings *ActionSettings, aquaServer string) *actions.TeamsAction {
	return &actions.TeamsAction{
		Name:       sourceSettings.Name,
		AquaServer: aquaServer,
		Webhook:    sourceSettings.Url,
	}
}

func buildServiceNow(sourceSettings *ActionSettings) *actions.ServiceNowAction {
	serviceNow := &actions.ServiceNowAction{
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

func buildSlackAction(sourceSettings *ActionSettings, aqua string) *actions.SlackAction {
	return &actions.SlackAction{
		Name:       sourceSettings.Name,
		AquaServer: aqua,
		Url:        sourceSettings.Url,
	}
}

func buildEmailAction(sourceSettings *ActionSettings) *actions.EmailAction {
	return &actions.EmailAction{
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
func buildNexusIqAction(sourceSettings *ActionSettings) *actions.NexusIqAction {
	return &actions.NexusIqAction{
		Name:           sourceSettings.Name,
		Url:            sourceSettings.Url,
		User:           sourceSettings.User,
		Password:       sourceSettings.Password,
		OrganizationId: sourceSettings.OrganizationId,
	}
}

func buildDependencyTrackAction(sourceSettings *ActionSettings) *actions.DependencyTrackAction {
	return &actions.DependencyTrackAction{
		Name:   sourceSettings.Name,
		Url:    sourceSettings.Url,
		APIKey: sourceSettings.DependencyTrackAPIKey,
	}
}

func buildOpsGenieAction(sourceSettings *ActionSettings) *actions.OpsGenieAction {
	return &actions.OpsGenieAction{
		Name:           sourceSettings.Name,
		User:           sourceSettings.User,
		APIKey:         sourceSettings.Token,
		Responders:     sourceSettings.Assignee,
		VisibleTo:      sourceSettings.Recipients,
		PrioritySource: sourceSettings.Priority,
		Tags:           sourceSettings.Tags,
		Alias:          sourceSettings.Alias,
		Entity:         sourceSettings.Entity,
	}
}

func buildJiraAction(sourceSettings *ActionSettings) *actions.JiraAPI {
	jiraApi := &actions.JiraAPI{
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
		SprintId:        actions.NotConfiguredSprintId,
		BoardName:       sourceSettings.BoardName,
	}

	if len(jiraApi.Assignee) == 0 {
		jiraApi.Assignee = []string{jiraApi.User}
	}
	return jiraApi
}

func buildExecAction(sourceSettings *ActionSettings) (*actions.ExecClient, error) {
	if len(sourceSettings.InputFile) <= 0 && len(sourceSettings.ExecScript) <= 0 {
		return nil, fmt.Errorf("exec action requires either input-file or exec-script to be set")
	}

	if len(sourceSettings.InputFile) > 0 && len(sourceSettings.ExecScript) > 0 {
		return nil, fmt.Errorf("exec action only takes either input-file or exec-script, not both")
	}

	ec := &actions.ExecClient{
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

func buildHTTPAction(sourceSettings *ActionSettings) (*actions.HTTPClient, error) {
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

	hc := &actions.HTTPClient{
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

func buildKubernetesAction(sourceSettings *ActionSettings) (*actions.KubernetesClient, error) {
	if !actions.IsK8s() {
		if sourceSettings.KubeConfigFile == "" {
			return nil, fmt.Errorf("kubernetes config file needs to be set in config yaml")
		}
	}

	if sourceSettings.KubeNamespace == "" {
		return nil, fmt.Errorf("kubernetes namespace needs to be set in config yaml")
	}

	return &actions.KubernetesClient{
		Name:              sourceSettings.Name,
		KubeNamespace:     sourceSettings.KubeNamespace,
		KubeConfigFile:    sourceSettings.KubeConfigFile,
		KubeLabelSelector: sourceSettings.KubeLabelSelector,
		KubeActions:       sourceSettings.KubeActions,
	}, nil
}

func buildDockerAction(sourceSettings *ActionSettings) (*actions.DockerClient, error) {
	if len(sourceSettings.DockerImageName) < 0 {
		return nil, fmt.Errorf("docker action requires an image name")
	}

	return &actions.DockerClient{
		Name:      sourceSettings.Name,
		ImageName: sourceSettings.DockerImageName,
		Cmd:       sourceSettings.DockerCmd,
		Volumes:   sourceSettings.DockerVolumes,
		Env:       sourceSettings.DockerEnv,
		Network:   sourceSettings.DockerNetwork,
	}, nil
}

func buildAWSSecurityHubAction(sourceSettings *ActionSettings) (*actions.AWSSecurityHubClient, error) {
	return &actions.AWSSecurityHubClient{Name: sourceSettings.Name}, nil
}

func buildPagerdutyAction(sourceSettings *ActionSettings) (*actions.PagerdutyClient, error) {
	return &actions.PagerdutyClient{
		Name:       sourceSettings.Name,
		AuthToken:  sourceSettings.PagerdutyAuthToken,
		RoutingKey: sourceSettings.PagerdutyRoutingKey,
	}, nil
}
