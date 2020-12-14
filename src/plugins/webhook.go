package plugins

import (
	"fmt"
	"formatting"
	"io/ioutil"
	"layout"
	"log"
	"net/http"
	"settings"
	"strings"
)

type WebhookPlugin struct {
	Url string
	WebhookSettings *settings.Settings
}

func (webhook *WebhookPlugin) Init() error {
	log.Printf("Starting Webhook plugin %q, for sending to %q",
		webhook.WebhookSettings.PluginName, webhook.Url)
	return nil
}

func (webhook *WebhookPlugin) Send(content map[string]string) error {
	log.Printf("Sending webhook to %q", webhook.Url)
	data := content["src"]
	resp, err := http.Post( webhook.Url, "application/json", strings.NewReader(data))
	if err != nil {
		log.Printf("Sending webhook Error: %v", err)
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Sending %q Error: %v", webhook.WebhookSettings.PluginName, err)
		return err
	}

	if resp.StatusCode != http.StatusOK {
		msg := "Sending webhook wrong status: %q. Body: %s"
		log.Printf(msg,resp.StatusCode, body)
		return fmt.Errorf(msg, resp.StatusCode, body)
	}
	log.Printf("Sending Webhook to %q was successful!", webhook.WebhookSettings.PluginName)
	return nil
}

func (webhook *WebhookPlugin) Terminate() error {
	log.Printf("Webhook plugin %q terminated.", webhook.WebhookSettings.PluginName)
	return nil
}

func (webhook *WebhookPlugin) GetLayoutProvider() layout.LayoutProvider {
	// Todo: This is MOCK. Because Formatting isn't need for Webook ))
	// todo: The App should work with `return nil`
	return new(formatting.HtmlProvider)
}

func (webhook *WebhookPlugin) GetSettings() *settings.Settings {
	return webhook.WebhookSettings
}


