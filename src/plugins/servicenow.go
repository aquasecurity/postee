package plugins

import (
	"formatting"
	"layout"
	"log"
	servicenow "servicenow-api"
	"settings"
)

type ServiceNowPlugin struct {
	User               string
	Password           string
	Instance           string
	Table              string
	ServiceNowSettings *settings.Settings
	layoutProvider     layout.LayoutProvider
}

func (sn *ServiceNowPlugin) Init() error {
	log.Printf("Starting ServiceNow plugin %q....", sn.ServiceNowSettings.PluginName)
	log.Printf("Your ServiceNow Table is %q on '%s.%s'", sn.Table, sn.Instance, servicenow.BaseServer)
	sn.layoutProvider = new(formatting.HtmlProvider)
	return nil
}

func (sn *ServiceNowPlugin) Send(content map[string]string) error {
	log.Printf("Sending via ServiceNow %q", sn.ServiceNowSettings.PluginName)
	log.Printf("Sending via ServiceNow %q was successful!", sn.ServiceNowSettings.PluginName)
	body := content["description"]

	err:= servicenow.InsertRecordToTable(sn.User, sn.Password, sn.Instance, sn.Table, body)
	if err != nil {
		log.Println("ServiceNow Error:", err)
	}
	return err
}

func (sn *ServiceNowPlugin) Terminate() error {
	log.Printf("ServiceNow plugin %q terminated", sn.ServiceNowSettings.PluginName)
	return nil
}

func (sn *ServiceNowPlugin) GetLayoutProvider() layout.LayoutProvider {
	return sn.layoutProvider
}

func (sn *ServiceNowPlugin) GetSettings() *settings.Settings {
	return sn.ServiceNowSettings
}
