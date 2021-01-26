package plugins

import (
	"formatting"
	"layout"
	"log"
	"settings"
)

type SplunkPlugin struct {
	Url           string
	SplunkSettings *settings.Settings
	splunkLayout   layout.LayoutProvider
}

func (splunk *SplunkPlugin) Init() error {
	splunk.splunkLayout = new(formatting.HtmlProvider)
	log.Printf("Starting Splunk plugin %q....", splunk.SplunkSettings.PluginName)
	return nil
}

func (splunk *SplunkPlugin) Send(map[string]string) error{
	log.Printf("Sending a message to %q", splunk.SplunkSettings.PluginName)
	return nil
}

func (splunk *SplunkPlugin)  Terminate() error {
	log.Printf("Splunk plugin %q terminated", splunk.SplunkSettings.PluginName)
	return nil
}

func (splunk *SplunkPlugin) GetLayoutProvider() layout.LayoutProvider {
	return splunk.splunkLayout
}

func (splunk *SplunkPlugin) GetSettings() *settings.Settings {
	return splunk.SplunkSettings
}