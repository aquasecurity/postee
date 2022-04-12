package outputs

import (
	"encoding/json"
	"github.com/aquasecurity/postee/v2/formatting"
	"github.com/aquasecurity/postee/v2/layout"
	"log"

	"github.com/opsgenie/opsgenie-go-sdk-v2/alert"
	"github.com/opsgenie/opsgenie-go-sdk-v2/client"
)

const defaultPriority = alert.P3

type OpsGenieOutput struct {
	Name       string
	User       string
	APIKey     string
	Responders []string
	VisibleTo  []string
}

func (ops *OpsGenieOutput) GetName() string {
	return ops.Name
}

func (ops *OpsGenieOutput) Init() error {
	log.Printf("Starting OpsGenie output %q....", ops.Name)
	return nil
}

func getUserResponders(users []string) []alert.Responder {
	if len(users) == 0 {
		return nil
	}
	responders := []alert.Responder{}
	for _, user := range users {
		responder := alert.Responder{Type: alert.UserResponder, Username: user}
		responders = append(responders, responder)
	}
	return responders
}

func getString(i interface{}) string {
	if i == nil {
		return ""
	}
	return i.(string)
}

func (ops *OpsGenieOutput) convertResultToOpsGenie(title string, content map[string]interface{}) *alert.CreateAlertRequest {
	description := getString(content["description"])
	alias := getString(content["alias"])
	entity := getString(content["entity"])
	priority := defaultPriority
	if content["priority"] != nil {
		priority = alert.Priority(getString(content["priority"]))
	}
	var tags []string
	if content["tags"] != nil {
		tags = content["tags"].([]string)
	}

	return &alert.CreateAlertRequest{
		Message:     title,
		Description: description,
		Alias:       alias,
		Entity:      entity,
		Priority:    priority,
		Tags:        tags,
		Responders:  getUserResponders(ops.Responders),
		VisibleTo:   getUserResponders(ops.VisibleTo),
	}
}

func (ops *OpsGenieOutput) Send(input map[string]string) error {
	data := map[string]interface{}{}
	if err := json.Unmarshal([]byte(input["description"]), &data); err != nil {
		return err
	}
	r := ops.convertResultToOpsGenie(input["title"], data)
	r.User = ops.User

	alertClient, err := alert.NewClient(&client.Config{
		ApiKey: ops.APIKey,
	})
	if err != nil {
		return err
	}

	alertResult, err := alertClient.Create(nil, r)
	if err != nil {
		return err
	}

	log.Printf("Sending to %q was successful: %s", ops.Name, alertResult.Result)
	return nil
}

func (*OpsGenieOutput) Terminate() error {
	return nil
}

func (ops *OpsGenieOutput) GetLayoutProvider() layout.LayoutProvider {
	/*TODO come up with smaller interface that doesn't include GetLayoutProvider()*/
	return new(formatting.SlackMrkdwnProvider)
}
