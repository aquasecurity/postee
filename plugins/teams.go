package plugins

import (
	"github.com/aquasecurity/postee/formatting"
	"github.com/aquasecurity/postee/layout"
	"github.com/aquasecurity/postee/settings"
	"github.com/aquasecurity/postee/utils"
	"log"

	msteams "github.com/aquasecurity/postee/teams"
)

const (
	teamsSizeLimit = 18000 // 28 KB is an approximate limit for MS Teams
)

type TeamsPlugin struct {
	teamsLayout   layout.LayoutProvider
	TeamsSettings *settings.Settings
	Webhook       string
}

func (teams *TeamsPlugin) Init() error {
	log.Printf("Starting MS Teams plugin %q....", teams.TeamsSettings.PluginName)
	teams.teamsLayout = new(formatting.HtmlProvider)
	return nil
}

func (teams *TeamsPlugin) Send(input map[string]string) error {
	log.Printf("Sending to MS Teams via %q...", teams.TeamsSettings.PluginName)
	utils.Debug("Title for %q: %q\n", teams.TeamsSettings.PluginName, input["title"])
	utils.Debug("Url(s) for %q: %q\n", teams.TeamsSettings.PluginName, input["url"])
	utils.Debug("Webhook for %q: %q\n", teams.TeamsSettings.PluginName, teams.Webhook)
	utils.Debug("Length of Description for %q: %d/%d\n",
		teams.TeamsSettings.PluginName, len(input["description"]), teamsSizeLimit)

	var body string
	if len(input["description"]) > teamsSizeLimit {
		utils.Debug("MS Team plugin will send SHORT message\n")
		body = buildShortMessage(teams.TeamsSettings.AquaServer, input["url"], teams.teamsLayout)
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
	log.Printf("Sending to MS Teams via %q was successful!", teams.TeamsSettings.PluginName)
	return nil
}

func (teams *TeamsPlugin) Terminate() error {
	log.Printf("MS Teams plugin %q terminated", teams.TeamsSettings.PluginName)
	return nil
}

func (teams *TeamsPlugin) GetLayoutProvider() layout.LayoutProvider {
	return teams.teamsLayout
}

func (teams *TeamsPlugin) GetSettings() *settings.Settings {
	return teams.TeamsSettings
}
