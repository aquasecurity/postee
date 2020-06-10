package teams_api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"utils"
)

type MSTeamsChannelMessage struct {
	Text string `json:"text"`
}

func CreateMessageByWebhook(webhook, content string) error {
	message := &MSTeamsChannelMessage{
		Text: content,
	}
	mb, err := json.Marshal(message)
	if err != nil {
		return err
	}
	utils.Debug("Data for sending to %q: %q\n", webhook, string(mb))
	r := bytes.NewReader(mb)
	client := http.DefaultClient
	reg, err := http.NewRequest("POST", webhook, r)
	if err != nil { return err}
	reg.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(reg)
	if err != nil {		return err	}

	defer resp.Body.Close()
	if message, _ := ioutil.ReadAll(resp.Body); resp.StatusCode != http.StatusOK {
		return fmt.Errorf("InsertRecordToTable Error: %q\n%s",resp.Status, message)
	} else {
		utils.Debug("Response body: %q\n", message)
	}
	return nil
}
