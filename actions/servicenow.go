package actions

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"time"

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
	// parse data
	i, err := strconv.ParseInt(content["date"], 10, 64)
	if err != nil {
		return fmt.Errorf("can't convert data stamp: %w", err)
	}
	date := time.Unix(i, 0)
	// parse severity
	severity, err := strconv.Atoi(content["severity"])
	if err != nil {
		return fmt.Errorf("can't convert severity: %w", err)
	}

	d := &servicenow.ServiceNowData{
		Opened:           date,
		ShortDescription: content["title"],
		Caller:           "abel.tuter", // TODO switch to "Aqua security"
		Category:         "SoftWare",   // TODO switch to "Security Image Scan results"
		Impact:           severity,
		Urgency:          severity,
		State:            1,       // TODO what value should we use
		Subcategory:      "Email", // TODO switch to "Security incident"
		WorkNotes:        "[code]" + content["description"] + "[/code]",
		Description:      content["summary"],
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
