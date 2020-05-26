package plugins

import (
	"formatting"
	"layout"
	"log"
	"settings"
)

type SlackPlugin struct {
	User          string
	Password      string
	SlackSettings *settings.Settings
}

func (slack *SlackPlugin) Init() error {
	log.Printf("Starting Slack plugin %q....", slack.SlackSettings.PluginName)
	return nil
}

func (slack *SlackPlugin) Send(data map[string]string) error {
	/*
	-X POST -H 'Content-type: application/json' --data '{"text":"Hello, World!"}' YOUR_WEBHOOK_URL_HERE
	 */

	log.Printf("Sending via Slack %q", slack.SlackSettings.PluginName)
	log.Printf("Title: %q", data["title"])
	log.Printf("Description %q", data["description"])
	return nil
}

func (slack *SlackPlugin) Terminate() error {
	log.Printf("Slack plugin %q terminated", slack.SlackSettings.PluginName)
	return nil
}

func (slack *SlackPlugin) GetLayoutProvider() layout.LayoutProvider {
	return new(formatting.MrkdwnProvider)
}

func (slack *SlackPlugin) GetSettings() *settings.Settings {
	return slack.SlackSettings
}
