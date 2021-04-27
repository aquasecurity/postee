package plugins

import (
	"fmt"
	"github.com/aquasecurity/postee/formatting"
	"github.com/aquasecurity/postee/layout"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

type WebhookPlugin struct {
	Name string
	Url  string
}

func (webhook *WebhookPlugin) Init() error {
	log.Printf("Starting Webhook plugin %q, for sending to %q",
		webhook.Name, webhook.Url)
	return nil
}

func (webhook *WebhookPlugin) Send(content map[string]string) error {
	log.Printf("Sending webhook to %q", webhook.Url)
	data := content["src"]
	resp, err := http.Post(webhook.Url, "application/json", strings.NewReader(data))
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

func (webhook *WebhookPlugin) Terminate() error {
	log.Printf("Webhook plugin %q terminated.", webhook.Name)
	return nil
}

func (webhook *WebhookPlugin) GetLayoutProvider() layout.LayoutProvider {
	// Todo: This is MOCK. Because Formatting isn't need for Webhook
	// todo: The App should work with `return nil`
	return new(formatting.HtmlProvider)
}
