package outputs

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

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
	// parse date
	i, err := strconv.ParseInt(content["date"], 10, 64)
	if err != nil {
		return data.OutputResponse{}, fmt.Errorf("can't convert data stamp: %w", err)
	}
	date := time.Unix(i, 0)
	// parse severity
	severity, err := strconv.Atoi(content["severity"])
	if err != nil {
		return data.OutputResponse{}, fmt.Errorf("can't convert severity: %w", err)
	}

	d := &servicenow.ServiceNowData{
		Opened:           date,
		ShortDescription: content["title"],
		Caller:           sn.User,
		Category:         content["category"],
		Impact:           severity,
		Urgency:          severity,
		Subcategory:      content["subcategory"],
		AssignedTo:       content["assignedTo"],
		AssignmentGroup:  content["assignedGroup"],
		WorkNotes:        "[code]" + content["description"] + "[/code]",
		Description:      content["summary"],
	}

	body, err := json.Marshal(d)
	if err != nil {
		log.Logger.Error(fmt.Errorf("serviceNow Error: %w", err))
		return data.OutputResponse{}, errors.New("Error when trying to parse ServiceNow integration data")
	}

	resp, err := servicenow.InsertRecordToTable(sn.User, sn.Password, sn.Instance, sn.Table, body)
	if err != nil {
		log.Logger.Error("ServiceNow Error: ", err)
		return data.OutputResponse{}, errors.New("Failed inserting record to the ServiceNow table")
	}

	ticketLink := fmt.Sprintf("https://%s.service-now.com/nav_to.do?uri=%s.do?sys_id=%s", sn.Instance, sn.Table, resp.SysID)
	log.Logger.Infof("Successfully sent a message via ServiceNow %q, ID %q, Link %q", sn.Name, resp.SysID, ticketLink)
	return data.OutputResponse{Key: resp.SysID, Url: ticketLink, Name: sn.Name}, nil
}

func (sn *ServiceNowOutput) Terminate() error {
	log.Logger.Debugf("ServiceNow output %q terminated", sn.Name)
	return nil
}

func (sn *ServiceNowOutput) GetLayoutProvider() layout.LayoutProvider {
	return sn.layoutProvider
}
