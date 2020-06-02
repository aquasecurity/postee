package plugins

import (
	"formatting"
	"layout"
	"log"
	"settings"
)

type TeamsPlugin struct {
	TeamsSettings *settings.Settings
	teamsLayout   layout.LayoutProvider
	token         string
}

func (teams *TeamsPlugin) SetToken( t string ) {
	teams.token = t
}

func (teams *TeamsPlugin) Init() error {
	teams.teamsLayout = new(formatting.HtmlProvider)
	log.Printf("Starting MS Teams plugin %q....", teams.TeamsSettings.PluginName)
	return nil
}

func (teams *TeamsPlugin) Send(map[string]string) error {
	log.Printf("Sending to MS Teams via %q...", teams.TeamsSettings.PluginName)



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
