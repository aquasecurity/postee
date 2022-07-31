package outputs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/formatting"
	"github.com/aquasecurity/postee/v2/layout"
	"github.com/aquasecurity/postee/v2/log"

	slackAPI "github.com/aquasecurity/postee/v2/slack"
)

const (
	slackBlockLimit = 49
	SlackType       = "slack"
)

type SlackOutput struct {
	Name        string
	AquaServer  string
	Url         string
	slackLayout layout.LayoutProvider
}

func (slack *SlackOutput) GetType() string {
	return SlackType
}

func (slack *SlackOutput) GetName() string {
	return slack.Name
}

func (slack *SlackOutput) CloneSettings() *data.OutputSettings {
	return &data.OutputSettings{
		Name:   slack.Name,
		Url:    slack.Url,
		Enable: true,
		Type:   SlackType,
	}
}

func (slack *SlackOutput) Init() error {
	slack.slackLayout = new(formatting.SlackMrkdwnProvider)
	log.Logger.Infof("Successfully initialized Slack output %q", slack.Name)
	return nil
}

func clearSlackText(text string) string {
	s := strings.ReplaceAll(text, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func buildSlackBlock(title string, data []byte) []byte {
	var content bytes.Buffer
	content.WriteByte('{')
	content.WriteString("\"blocks\":")
	content.WriteByte('[')
	content.WriteString(title)
	content.Write(data)
	content.WriteByte(']')
	content.WriteByte('}')
	return content.Bytes()
}

func (slack *SlackOutput) Send(input map[string]string) (string, error) {
	log.Logger.Infof("Sending to Slack via %q", slack.Name)
	title := clearSlackText(slack.slackLayout.TitleH2(input["title"]))
	var body string
	if strings.HasSuffix(input["description"], ",") {
		body = strings.TrimSuffix(input["description"], ",")
	} else {
		body = input["description"]
	}
	body = clearSlackText(body)
	if !strings.HasPrefix(body, "[") {
		body = "[" + body + "]"
	}
	rawBlock := make([]data.SlackBlock, 0)
	err := json.Unmarshal([]byte(body), &rawBlock)
	if err != nil {
		log.Logger.Error(fmt.Errorf("unable to parse json: %w", err))
		return EmptyID, err
	}

	length := len(rawBlock)

	if length >= slackBlockLimit {
		message := buildShortMessage(slack.AquaServer, input["url"], slack.slackLayout)
		if err := slackAPI.SendToUrl(slack.Url, buildSlackBlock(title, []byte(message))); err != nil {
			return EmptyID, err
		}
		log.Logger.Debugf("Sending to Slack %q was successful!", slack.Name)
	} else {
		for n := 0; n < length; {
			d := length - n
			if d >= 49 {
				d = 49
			}
			cutData, _ := json.Marshal(rawBlock[n : n+d])
			cutData = cutData[1 : len(cutData)-1]
			if err := slackAPI.SendToUrl(slack.Url, buildSlackBlock(title, cutData)); err != nil {
				log.Logger.Error(fmt.Errorf("sending to Slack via %q was finished with error: %w", slack.Name, err))
				return EmptyID, err
			} else {
				log.Logger.Debugf("Sending to Slack [%d/%d part] via %q was successful!",
					int(n/49)+1, int(length/49)+1,
					slack.Name)
			}
			n += d
		}
	}
	return EmptyID, nil
}

func (slack *SlackOutput) Terminate() error {
	log.Logger.Debugf("Slack output %q terminated", slack.Name)
	return nil
}

func (slack *SlackOutput) GetLayoutProvider() layout.LayoutProvider {
	return slack.slackLayout
}
