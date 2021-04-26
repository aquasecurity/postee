package plugins

import (
	"github.com/aquasecurity/postee/formatting"
	"github.com/aquasecurity/postee/layout"
	"github.com/aquasecurity/postee/utils"
	"log"

	msteams "github.com/aquasecurity/postee/teams"
)

const (
	teamsSizeLimit = 18000 // 28 KB is an approximate limit for MS Teams
)

type TeamsPlugin struct {
	Name        string
	AquaServer  string
	teamsLayout layout.LayoutProvider
	Webhook     string
}

func (teams *TeamsPlugin) Init() error {
	log.Printf("Starting MS Teams plugin %q....", teams.Name)
	teams.teamsLayout = new(formatting.HtmlProvider)
	return nil
}

func (teams *TeamsPlugin) Send(input map[string]string) error {
	log.Printf("Sending to MS Teams via %q...", teams.Name)
	utils.Debug("Title for %q: %q\n", teams.Name, input["title"])
	utils.Debug("Url(s) for %q: %q\n", teams.Name, input["url"])
	utils.Debug("Webhook for %q: %q\n", teams.Name, teams.Webhook)
	utils.Debug("Length of Description for %q: %d/%d\n",
		teams.Name, len(input["description"]), teamsSizeLimit)

	var body string
	if len(input["description"]) > teamsSizeLimit {
		utils.Debug("MS Team plugin will send SHORT message\n")
		body = buildShortMessage(teams.AquaServer, input["url"], teams.teamsLayout)
	} else {
		utils.Debug("MS Team plugin will send LONG message\n")
		body = input["description"]
	}
	utils.Debug("Message is: %q\n", body)

	err := msteams.CreateMessageByWebhook(teams.Webhook, teams.teamsLayout.TitleH2(input["title"])+body)
	if err != nil {
		log.Printf("TeamsPlugin Send Error: %v", err)
		return err
	}
	log.Printf("Sending to MS Teams via %q was successful!", teams.Name)
	return nil
}

func (teams *TeamsPlugin) Terminate() error {
	log.Printf("MS Teams plugin %q terminated", teams.Name)
	return nil
}

func (teams *TeamsPlugin) GetLayoutProvider() layout.LayoutProvider {
	return teams.teamsLayout
}
