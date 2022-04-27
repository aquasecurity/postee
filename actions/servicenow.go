package actions

import (
	"encoding/json"
	"log"

	"github.com/aquasecurity/postee/v2/formatting"
	"github.com/aquasecurity/postee/v2/layout"
	servicenow "github.com/aquasecurity/postee/v2/servicenow"
)

type ServiceNowAction struct {
	Name           string
	User           string
	Password       string
	Instance       string
	Table          string
	layoutProvider layout.LayoutProvider
}

func (sn *ServiceNowAction) GetName() string {
	return sn.Name
}

func (sn *ServiceNowAction) Init() error {
	log.Printf("Starting ServiceNow action %q....", sn.Name)
	log.Printf("Your ServiceNow Table is %q on '%s.%s'", sn.Table, sn.Instance, servicenow.BaseServer)
	sn.layoutProvider = new(formatting.HtmlProvider)
	return nil
}

func (sn *ServiceNowAction) Send(content map[string]string) error {
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

func (sn *ServiceNowAction) Terminate() error {
	log.Printf("ServiceNow action %q terminated", sn.Name)
	return nil
}

func (sn *ServiceNowAction) GetLayoutProvider() layout.LayoutProvider {
	return sn.layoutProvider
}
