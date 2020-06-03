package teams_api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
)

type MSTeamsChannelMessage struct {
	Text string `json:"text"`
}

func prnLogResponse(body io.ReadCloser) string {
	defer body.Close()
	message, _ := ioutil.ReadAll(body)
	return  string(message)
}

func CreateMessageByWebhook(webhook, content string) error {
	message := &MSTeamsChannelMessage{
		Text: content,
	}
	mb, err := json.Marshal(message)
	if err != nil {
		return err
	}
	r := bytes.NewReader(mb)
	client := http.DefaultClient
	reg, err := http.NewRequest("POST", webhook, r)
	if err != nil { return err}
	reg.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(reg)
	if err != nil {		return err	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("InsertRecordToTable Error: %q\n%s",resp.Status, prnLogResponse(resp.Body))
	}
	return nil
}
