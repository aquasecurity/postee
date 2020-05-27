package plugins

import (
	"bytes"
	"fmt"
	"formatting"
	"io/ioutil"
	"layout"
	"log"
	"net/http"
	"settings"
	"strings"
)

type SlackPlugin struct {
	Url           string
	SlackSettings *settings.Settings
	slackLayout   layout.LayoutProvider
}

func (slack *SlackPlugin) Init() error {
	slack.slackLayout = new(formatting.SlackMrkdwnProvider)
	log.Printf("Starting Slack plugin %q....", slack.SlackSettings.PluginName)
	return nil
}

func clearSlackText (text string) string  {
	s := strings.ReplaceAll(text, "&", "&amp;")
	s = strings.ReplaceAll( s, "<", "&lt;")
	s = strings.ReplaceAll( s, ">", "&gt;")
	return s
}

func (slack *SlackPlugin) Send(data map[string]string) error {
	log.Printf("Sending via Slack %q", slack.SlackSettings.PluginName)
	var content bytes.Buffer
	title := slack.slackLayout.TitleH2(data["title"])

	var body string
	if strings.HasSuffix(data["description"], ",") {
		body = strings.TrimSuffix(data["description"], ",")
	} else {
		body = data["description"]
	}
	fmt.Fprintf( &content, "{\"blocks\":[%s %s]}", clearSlackText(title), clearSlackText(body))
	r := bytes.NewReader(content.Bytes())
	resp, err := http.Post( slack.Url, "application/json", r)
	if err != nil {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		log.Println("Blocks:", content.String())
		defer resp.Body.Close()
		message, _ := ioutil.ReadAll(resp.Body)
		log.Printf("Sending has a problem. Status: %q. Message: %q", resp.Status,string(message))
	} else {
		log.Printf("Sending to %q was successful!", slack.SlackSettings.PluginName)
	}
	return nil
}

func (slack *SlackPlugin) Terminate() error {
	log.Printf("Slack plugin %q terminated", slack.SlackSettings.PluginName)
	return nil
}

func (slack *SlackPlugin) GetLayoutProvider() layout.LayoutProvider {
	return slack.slackLayout
}

func (slack *SlackPlugin) GetSettings() *settings.Settings {
	return slack.SlackSettings
}
