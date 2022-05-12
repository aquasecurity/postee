package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/opsgenie/opsgenie-go-sdk-v2/alert"
	"github.com/opsgenie/opsgenie-go-sdk-v2/client"

	"github.com/aquasecurity/postee/v2/formatting"
	"github.com/aquasecurity/postee/v2/layout"
)

const defaultPriority = alert.P3

type OpsGenieOutput struct {
	Name           string
	User           string
	APIKey         string
	Responders     []string
	VisibleTo      []string
	Tags           []string
	PrioritySource string
	priority       alert.Priority

	client *alert.Client
}

func (ops *OpsGenieOutput) GetName() string {
	return ops.Name
}

func (ops *OpsGenieOutput) Init() (err error) {
	ops.client, err = alert.NewClient(&client.Config{
		ApiKey: ops.APIKey,
	})
	if err != nil {
		return
	}

	if ops.PrioritySource != "" {
		ops.priority = alert.Priority(ops.PrioritySource)
	} else {
		ops.priority = defaultPriority
	}

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

func (ops *OpsGenieOutput) convertResultToOpsGenie(title string, content map[string]interface{}) *alert.CreateAlertRequest {
	description := fmt.Sprint(content["description"])
	alias := fmt.Sprint(content["alias"])
	entity := fmt.Sprint(content["entity"])

	priority := ops.priority
	if content["priority"] != nil {
		priority = alert.Priority(fmt.Sprint(content["priority"]))
	}
	tags := ops.Tags
	if content["tags"] != nil {
		switch content["tags"].(type) {
		case []string:
			tags = append(tags, content["tags"].([]string)...)
		case string:
			tags = append(tags, strings.Split(content["tags"].(string), ",")...)
		}
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

	alertResult, err := ops.client.Create(context.Background(), r)
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
