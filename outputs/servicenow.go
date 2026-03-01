package outputs

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
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
	Url            string // ServiceNow instance URL (new behaviour). If set, used as-is; otherwise Instance + BaseServer is used (legacy).
	Instance       string // Legacy: instance name (e.g. dev12345) for https://<instance>.service-now.com/
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
		Name:         sn.Name,
		User:         sn.User,
		Url:          sn.Url,
		InstanceName: sn.Instance,
		BoardName:    sn.Table,
		Enable:       true,
		Type:         serviceNowType,
	}
}

func (sn *ServiceNowOutput) Init() error {
	sn.layoutProvider = new(formatting.HtmlProvider)

	log.Logger.Infof("Successfully initialized ServiceNow output %q", sn.Name)
	if sn.Url != "" {
		log.Logger.Debugf("Your ServiceNow Table is %q at %q (instance URL)", sn.Table, sn.Url)
	} else {
		log.Logger.Debugf("Your ServiceNow Table is %q on %s.%s (legacy)", sn.Table, sn.Instance, servicenow.BaseServer)
	}
	return nil
}

func (sn *ServiceNowOutput) Send(content map[string]string) (data.OutputResponse, error) {
	log.Logger.Infof("Sending to ServiceNow via %q", sn.Name)
	// parse date
	date := ""
	if i, err := strconv.ParseInt(content["date"], 10, 64); err == nil {
		date = time.Unix(i, 0).Format("2006-01-02 15:04:05")
	}

	// parse severity
	severity := 3 // default ServiceNow value
	if s, err := strconv.Atoi(content["severity"]); err == nil {
		severity = s
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

	resp, err := servicenow.InsertRecordToTable(sn.User, sn.Password, sn.Url, sn.Instance, sn.Table, body)
	if err != nil {
		log.Logger.Error("ServiceNow Error: ", err)
		return data.OutputResponse{}, errors.New("Failed inserting record to the ServiceNow table")
	}

	var baseURL string
	if sn.Url != "" {
		baseURL = strings.TrimSuffix(sn.Url, "/")
	} else {
		baseURL = fmt.Sprintf("https://%s.%s", sn.Instance, servicenow.BaseServer)
		baseURL = strings.TrimSuffix(baseURL, "/")
	}
	ticketLink := fmt.Sprintf("%s/nav_to.do?uri=%s.do?sys_id=%s", baseURL, sn.Table, resp.SysID)
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
