package plugins

import (
	"bytes"
	"data"
	"encoding/json"
	"formatting"
	"io"
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

func prnLogResponse(body io.ReadCloser) string {
	defer body.Close()
	message, _ := ioutil.ReadAll(body)
	return  string(message)
}

func (slack *SlackPlugin) Send(input map[string]string) error {
	log.Printf("Sending via Slack %q", slack.SlackSettings.PluginName)
	title := clearSlackText(slack.slackLayout.TitleH2(input["title"]))
	var body string
	if strings.HasSuffix(input["description"], ",") {
		body = strings.TrimSuffix(input["description"], ",")
	} else {
		body = input["description"]
	}
	body = "[" + clearSlackText(body)+"]"
	rawBlock := make([]data.SlackBlock, 0)
	err := json.Unmarshal([]byte(body), &rawBlock)
	if err != nil {
		log.Printf("Unmarshal slack sending error: %v", err)
		return err
	}

	length := len(rawBlock)
	for n := 0; n < length; {
		d := length-n
		if d >= 49 {
			d = 49
		}
		cutData, _ := json.Marshal(rawBlock[n:n+d])
		cutData = cutData[1:len(cutData)-1]
		var content bytes.Buffer
		content.WriteByte('{')
		content.WriteString("\"blocks\":")
		content.WriteByte('[')
		content.WriteString(title)
		content.Write(cutData)
		content.WriteByte(']')
		content.WriteByte('}')
		r := bytes.NewReader(content.Bytes())
		resp, err := http.Post( slack.Url, "application/json", r)
		if err != nil {
			log.Printf("Post request to Slack Error: %v", err)
			return err
		}
		if resp.StatusCode != http.StatusOK {
			log.Printf("Sending had a problem. Status: %q. Message: %q",
				resp.Status,prnLogResponse(resp.Body))
		} else {
			log.Printf("Sending [%d/%d part] to %q was successful!",
				int(n/49)+1,int(length/49)+1,
				slack.SlackSettings.PluginName)
		}
		n += d
	}
	log.Printf("Sending via Slack %q was successful!", slack.SlackSettings.PluginName)
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
