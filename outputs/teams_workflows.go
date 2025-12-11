package outputs

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/postee/v2/formatting"
	"github.com/aquasecurity/postee/v2/layout"
	"github.com/aquasecurity/postee/v2/log"

	"github.com/aquasecurity/postee/v2/data"
	msteams "github.com/aquasecurity/postee/v2/teams"
)

const (
	teamsWorkflowsSizeLimit = 18000 // Similar limit as legacy Teams
	TeamsWorkflowsType      = "teamsworkflows"
)

// TeamsWorkflowsOutput implements the new Microsoft Teams Workflows webhook integration
// This replaces the deprecated Office 365 Connectors (Incoming Webhooks)
type TeamsWorkflowsOutput struct {
	Name        string
	AquaServer  string
	teamsLayout layout.LayoutProvider
	Webhook     string
}

func (teams *TeamsWorkflowsOutput) GetType() string {
	return TeamsWorkflowsType
}

func (teams *TeamsWorkflowsOutput) GetName() string {
	return teams.Name
}

func (teams *TeamsWorkflowsOutput) CloneSettings() *data.OutputSettings {
	return &data.OutputSettings{
		Name:   teams.Name,
		Url:    teams.Webhook,
		Enable: true,
		Type:   TeamsWorkflowsType,
	}
}

func (teams *TeamsWorkflowsOutput) Init() error {
	teams.teamsLayout = new(formatting.HtmlProvider)

	log.Logger.Infof("Successfully initialized MS Teams Workflows output %q", teams.Name)
	return nil
}

func (teams *TeamsWorkflowsOutput) Send(input map[string]string) (data.OutputResponse, error) {
	log.Logger.Infof("Sending to MS Teams Workflows via %q", teams.Name)
	log.Logger.Debugf("Title for %q: %q", teams.Name, input["title"])
	log.Logger.Debugf("Url(s) for %q: %q", teams.Name, input["url"])
	log.Logger.Debugf("Webhook for %q: %q", teams.Name, teams.Webhook)
	log.Logger.Debugf("Length of Description for %q: %d/%d",
		teams.Name, len(input["description"]), teamsWorkflowsSizeLimit)

	var body string
	if len(input["description"]) > teamsWorkflowsSizeLimit {
		log.Logger.Debugf("MS Teams Workflows output will send SHORT message")
		body = buildShortMessage(teams.AquaServer, input["url"], teams.teamsLayout)
	} else {
		log.Logger.Debugf("MS Teams Workflows output will send LONG message")
		body = input["description"]
	}

	// Clean up HTML tags for card text display
	body = cleanupForAdaptiveCard(body)

	log.Logger.Debugf("Message is: %q", body)

	title := input["title"]
	if title == "" {
		title = "Postee Notification"
	}

	err := msteams.CreateWorkflowsMessage(teams.Webhook, title, body)
	if err != nil {
		log.Logger.Error(fmt.Errorf("TeamsWorkflowsOutput Send Error: %w", err))
		return data.OutputResponse{}, err
	}

	log.Logger.Infof("Sending to MS Teams Workflows via %q was successful!", teams.Name)
	return data.OutputResponse{}, nil
}

func (teams *TeamsWorkflowsOutput) Terminate() error {
	log.Logger.Debugf("MS Teams Workflows output %q terminated", teams.Name)
	return nil
}

func (teams *TeamsWorkflowsOutput) GetLayoutProvider() layout.LayoutProvider {
	return teams.teamsLayout
}

// cleanupForAdaptiveCard converts HTML content to a format suitable for Adaptive Cards
// Adaptive Cards support a subset of markdown formatting
func cleanupForAdaptiveCard(content string) string {
	// Convert common HTML elements to text/markdown equivalents
	replacements := map[string]string{
		"<br>":      "\n",
		"<br/>":     "\n",
		"<br />":    "\n",
		"<p>":       "",
		"</p>":      "\n\n",
		"<b>":       "**",
		"</b>":      "**",
		"<strong>":  "**",
		"</strong>": "**",
		"<i>":       "_",
		"</i>":      "_",
		"<em>":      "_",
		"</em>":     "_",
		"<h1>":      "# ",
		"</h1>":     "\n",
		"<h2>":      "## ",
		"</h2>":     "\n",
		"<h3>":      "### ",
		"</h3>":     "\n",
		"<ul>":      "",
		"</ul>":     "",
		"<ol>":      "",
		"</ol>":     "",
		"<li>":      "• ",
		"</li>":     "\n",
		"&nbsp;":    " ",
		"&lt;":      "<",
		"&gt;":      ">",
		"&amp;":     "&",
		"&quot;":    "\"",
	}

	result := content
	for old, new := range replacements {
		result = strings.ReplaceAll(result, old, new)
	}

	// Remove any remaining HTML tags
	result = stripHTMLTags(result)

	// Clean up multiple newlines
	for strings.Contains(result, "\n\n\n") {
		result = strings.ReplaceAll(result, "\n\n\n", "\n\n")
	}

	return strings.TrimSpace(result)
}

// stripHTMLTags removes any HTML tags from the content
func stripHTMLTags(content string) string {
	var result strings.Builder
	inTag := false

	for _, r := range content {
		if r == '<' {
			inTag = true
			continue
		}
		if r == '>' {
			inTag = false
			continue
		}
		if !inTag {
			result.WriteRune(r)
		}
	}

	return result.String()
}
