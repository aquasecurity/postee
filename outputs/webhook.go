package outputs

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/aquasecurity/postee/v2/formatting"
	"github.com/aquasecurity/postee/v2/layout"
)

type WebhookOutput struct {
	Name string
	Url  string
}

func (webhook *WebhookOutput) GetName() string {
	return webhook.Name
}

func (webhook *WebhookOutput) Init() error {
	log.Printf("Starting Webhook output %q, for sending to %q",
		webhook.Name, webhook.Url)
	return nil
}

func (webhook *WebhookOutput) Send(content map[string]string) error {
	log.Printf("Sending webhook to %q", webhook.Url)
	data := content["description"] //it's not supposed to work with legacy renderer
	client := http.Client{Timeout: time.Duration(120) * time.Second}
	resp, err := client.Post(webhook.Url, "application/json", strings.NewReader(data))
	if err != nil {
		log.Printf("Sending webhook Error: %v", err)
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Sending %q Error: %v", webhook.Name, err)
		return err
	}

	if resp.StatusCode != http.StatusOK {
		msg := "Sending webhook wrong status: %q. Body: %s"
		log.Printf(msg, resp.StatusCode, body)
		return fmt.Errorf(msg, resp.StatusCode, body)
	}
	log.Printf("Sending Webhook to %q was successful!", webhook.Name)
	return nil
}

func (webhook *WebhookOutput) Terminate() error {
	log.Printf("Webhook output %q terminated.", webhook.Name)
	return nil
}

func (webhook *WebhookOutput) GetLayoutProvider() layout.LayoutProvider {
	// Todo: This is MOCK. Because Formatting isn't need for Webhook
	// todo: The App should work with `return nil`
	return new(formatting.HtmlProvider)
}
