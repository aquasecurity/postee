package outputs

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"

	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/formatting"
	"github.com/aquasecurity/postee/v2/layout"
	"github.com/aquasecurity/postee/v2/log"
	servicenow "github.com/aquasecurity/postee/v2/servicenow"
)

const (
	serviceNowType = "serviceNow"
)

type ServiceNowOutput struct {
	Name           string
	User           string
	Password       string
	Instance       string
	Table          string
	layoutProvider layout.LayoutProvider
}

func (sn *ServiceNowOutput) GetType() string {
	return serviceNowType
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
		Type:         serviceNowType,
	}
}

func (sn *ServiceNowOutput) Init() error {
	sn.layoutProvider = new(formatting.HtmlProvider)

	log.Logger.Infof("Successfully initialized ServiceNow output %q", sn.Name)
	log.Logger.Debugf("Your ServiceNow Table is %q on '%s.%s'", sn.Table, sn.Instance, servicenow.BaseServer)
	return nil
}

func (sn *ServiceNowOutput) Send(content map[string]string) (data.OutputResponse, error) {
	log.Logger.Infof("Sending to ServiceNow via %q", sn.Name)
	d := &servicenow.ServiceNowData{
		ShortDescription: content["title"],
		WorkNotes:        "[code]" + content["description"] + "[/code]",
	}

	body, err := json.Marshal(d)
	if err != nil {
		log.Logger.Error(fmt.Errorf("serviceNow Error: %w", err))
		return data.OutputResponse{}, errors.New("Error when trying to parse ServiceNow integration data")
	}

	err = servicenow.InsertRecordToTable(sn.User, sn.Password, sn.Instance, sn.Table, body)
	if err != nil {
		log.Logger.Error("ServiceNow Error: ", err)
		return data.OutputResponse{}, errors.New("Failed inserting record to the ServiceNow table")
	}

	log.Logger.Debugf("Successfully sent a message via ServiceNow %q", sn.Name)
	return data.OutputResponse{}, nil
}

func (sn *ServiceNowOutput) Terminate() error {
	log.Logger.Debugf("ServiceNow output %q terminated", sn.Name)
	return nil
}

func (sn *ServiceNowOutput) GetLayoutProvider() layout.LayoutProvider {
	return sn.layoutProvider
}
