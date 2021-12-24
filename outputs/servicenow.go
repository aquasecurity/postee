package outputs

import (
	"encoding/json"

	"github.com/aquasecurity/postee/data"
	"github.com/aquasecurity/postee/formatting"
	"github.com/aquasecurity/postee/layout"
	"github.com/aquasecurity/postee/log"
	servicenow "github.com/aquasecurity/postee/servicenow"
)

type ServiceNowOutput struct {
	Name           string
	User           string
	Password       string
	Instance       string
	Table          string
	layoutProvider layout.LayoutProvider
}

func (sn *ServiceNowOutput) GetName() string {
	return sn.Name
}

func (sn *ServiceNowOutput) CloneSettings() *data.OutputSettings {
	return &data.OutputSettings{
		Name: sn.Name,
		User: sn.User,
		//password
		InstanceName: sn.Instance,
		BoardName:    sn.Table,
		Enable:       true,
		Type:         "serviceNow",
	}
}

func (sn *ServiceNowOutput) Init() error {
	log.Logger.Infof("Starting ServiceNow output %q....", sn.Name)
	log.Logger.Infof("Your ServiceNow Table is %q on '%s.%s'", sn.Table, sn.Instance, servicenow.BaseServer)
	sn.layoutProvider = new(formatting.HtmlProvider)
	return nil
}

func (sn *ServiceNowOutput) Send(content map[string]string) error {
	log.Logger.Infof("Sending via ServiceNow %q", sn.Name)
	d := &servicenow.ServiceNowData{
		ShortDescription: content["title"],
		WorkNotes:        "[code]" + content["description"] + "[/code]",
	}
	body, err := json.Marshal(d)
	if err != nil {
		log.Logger.Error("ServiceNow Error:", err)
		return err
	}
	err = servicenow.InsertRecordToTable(sn.User, sn.Password, sn.Instance, sn.Table, body)
	if err != nil {
		log.Logger.Error("ServiceNow Error:", err)
		return err
	}
	log.Logger.Infof("Sending via ServiceNow %q was successful!", sn.Name)
	return nil
}

func (sn *ServiceNowOutput) Terminate() error {
	log.Logger.Infof("ServiceNow output %q terminated", sn.Name)
	return nil
}

func (sn *ServiceNowOutput) GetLayoutProvider() layout.LayoutProvider {
	return sn.layoutProvider
}
