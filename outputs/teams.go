package outputs

import (
	"encoding/json"
	"fmt"

	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/formatting"
	"github.com/aquasecurity/postee/v2/layout"
	"github.com/aquasecurity/postee/v2/log"

	msteams "github.com/aquasecurity/postee/v2/teams"
)

const (
	teamsSizeLimit = 18000 // 28 KB is an approximate limit for MS Teams
	TeamsType      = "teams"
)

type TeamsOutput struct {
	Name        string
	AquaServer  string
	teamsLayout layout.LayoutProvider
	Webhook     string
}

func (teams *TeamsOutput) GetType() string {
	return TeamsType
}

func (teams *TeamsOutput) GetName() string {
	return teams.Name
}

func (teams *TeamsOutput) CloneSettings() *data.OutputSettings {
	return &data.OutputSettings{
		Name:   teams.Name,
		Url:    teams.Webhook,
		Enable: true,
		Type:   TeamsType,
	}
}

func (teams *TeamsOutput) Init() error {
	teams.teamsLayout = new(formatting.HtmlProvider)

	log.Logger.Infof("Successfully initialized MS Teams output %q", teams.Name)
	return nil
}

func (teams *TeamsOutput) Send(input map[string]string) (string, error) {
	log.Logger.Infof("Sending to MS Teams via %q", teams.Name)
	log.Logger.Debugf("Title for %q: %q", teams.Name, input["title"])
	log.Logger.Debugf("Url(s) for %q: %q", teams.Name, input["url"])
	log.Logger.Debugf("Webhook for %q: %q", teams.Name, teams.Webhook)
	log.Logger.Debugf("Length of Description for %q: %d/%d",
		teams.Name, len(input["description"]), teamsSizeLimit)

	var body string
	if len(input["description"]) > teamsSizeLimit {
		log.Logger.Debugf("MS Team output will send SHORT message")
		body = buildShortMessage(teams.AquaServer, input["url"], teams.teamsLayout)
	} else {
		log.Logger.Debugf("MS Team output will send LONG message")
		body = input["description"]
	}
	log.Logger.Debugf("Message is: %q", body)

	escaped, err := escapeJSON(body)
	if err != nil {
		log.Logger.Errorf("Error while escaping payload: %v", err)
		return EmptyID, err
	}

	err = msteams.CreateMessageByWebhook(teams.Webhook, teams.teamsLayout.TitleH2(input["title"])+escaped)

	if err != nil {
		log.Logger.Error(fmt.Errorf("TeamsOutput Send Error: %w", err))
		return EmptyID, err
	}

	log.Logger.Debugf("Sending to MS Teams via %q was successful!", teams.Name)
	return EmptyID, nil
}

func (teams *TeamsOutput) Terminate() error {
	log.Logger.Debugf("MS Teams output %q terminated", teams.Name)
	return nil
}

func (teams *TeamsOutput) GetLayoutProvider() layout.LayoutProvider {
	return teams.teamsLayout
}

func escapeJSON(s string) (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	// Trim the beginning and trailing " character
	return string(b[1 : len(b)-1]), nil
}
