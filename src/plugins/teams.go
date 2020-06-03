package plugins

import (
	"formatting"
	"layout"
	"log"
	"settings"

	msteams "teams-api"
)

type TeamsPlugin struct {
	teamsLayout   layout.LayoutProvider
	TeamsSettings *settings.Settings
	Webhook string
}

func (teams *TeamsPlugin) Init() error {
	log.Printf("Starting MS Teams plugin %q....", teams.TeamsSettings.PluginName)
	teams.teamsLayout = new(formatting.HtmlProvider)
	return nil
}

func (teams *TeamsPlugin) Send(input map[string]string) error {
	log.Printf("Sending to MS Teams via %q...", teams.TeamsSettings.PluginName)
	err := msteams.CreateMessageByWebhook(teams.Webhook, teams.teamsLayout.TitleH2(input["title"]) + input["description"])
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
