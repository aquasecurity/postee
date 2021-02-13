package plugins

import (
	"encoding/json"
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
	d := &servicenow.ServiceNowData{
		ShortDescription: content["title"],
		WorkNotes:        "[code]" + content["description"] + "[/code]",
	}
	body, err := json.Marshal(d)
	if err != nil {
		log.Println("ServiceNow Error:", err)
		return err
	}
	err = servicenow.InsertRecordToTable(sn.User, sn.Password, sn.Instance, sn.Table, body)
	if err != nil {
		log.Println("ServiceNow Error:", err)
		return err
	}
	log.Printf("Sending via ServiceNow %q was successful!", sn.ServiceNowSettings.PluginName)
	return nil
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
