package outputs

import (
	"encoding/json"
	"fmt"

	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/formatting"
	"github.com/aquasecurity/postee/v2/layout"
	"github.com/aquasecurity/postee/v2/log"
	servicenow "github.com/aquasecurity/postee/v2/servicenow"
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
	log.Logger.Infof("Init ServiceNow output %q", sn.Name)
	log.Logger.Debugf("Your ServiceNow Table is %q on '%s.%s'", sn.Table, sn.Instance, servicenow.BaseServer)
	sn.layoutProvider = new(formatting.HtmlProvider)
	return nil
}

func (sn *ServiceNowOutput) Send(content map[string]string) error {
	log.Logger.Infof("Sending to ServiceNow via %q", sn.Name)
	d := &servicenow.ServiceNowData{
		ShortDescription: content["title"],
		WorkNotes:        "[code]" + content["description"] + "[/code]",
	}
	body, err := json.Marshal(d)
	if err != nil {
		log.Logger.Error(fmt.Errorf("serviceNow Error: %w", err))
		return err
	}
	err = servicenow.InsertRecordToTable(sn.User, sn.Password, sn.Instance, sn.Table, body)
	if err != nil {
		log.Logger.Error("ServiceNow Error: ", err)
		return err
	}
	log.Logger.Debugf("Sending via ServiceNow %q was successful!", sn.Name)
	return nil
}

func (sn *ServiceNowOutput) Terminate() error {
	log.Logger.Debugf("ServiceNow output %q terminated", sn.Name)
	return nil
}

func (sn *ServiceNowOutput) GetLayoutProvider() layout.LayoutProvider {
	return sn.layoutProvider
}
