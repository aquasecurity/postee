package plugins

import (
	"encoding/json"
	"github.com/aquasecurity/postee/formatting"
	"github.com/aquasecurity/postee/layout"
	servicenow "github.com/aquasecurity/postee/servicenow"
	"log"
)

type ServiceNowPlugin struct {
	Name           string
	User           string
	Password       string
	Instance       string
	Table          string
	layoutProvider layout.LayoutProvider
}

func (sn *ServiceNowPlugin) Init() error {
	log.Printf("Starting ServiceNow plugin %q....", sn.Name)
	log.Printf("Your ServiceNow Table is %q on '%s.%s'", sn.Table, sn.Instance, servicenow.BaseServer)
	sn.layoutProvider = new(formatting.HtmlProvider)
	return nil
}

func (sn *ServiceNowPlugin) Send(content map[string]string) error {
	log.Printf("Sending via ServiceNow %q", sn.Name)
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
	log.Printf("Sending via ServiceNow %q was successful!", sn.Name)
	return nil
}

func (sn *ServiceNowPlugin) Terminate() error {
	log.Printf("ServiceNow plugin %q terminated", sn.Name)
	return nil
}

func (sn *ServiceNowPlugin) GetLayoutProvider() layout.LayoutProvider {
	return sn.layoutProvider
}
