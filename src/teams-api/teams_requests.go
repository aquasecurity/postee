package teams_api

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"utils"
)

func CreateMessageByWebhook(webhook, content string) error {
	var message bytes.Buffer
	fmt.Fprintf(&message, "{\"text\":\"%s\"}", content)

	utils.Debug("Data for sending to %q: %q\n", webhook, message.String())
	r := bytes.NewReader(message.Bytes())
	client := http.DefaultClient
	reg, err := http.NewRequest("POST", webhook, r)
	if err != nil { return err}
	reg.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(reg)
	if err != nil {		return err	}

	defer resp.Body.Close()
	if message, _ := ioutil.ReadAll(resp.Body); resp.StatusCode != http.StatusOK {
		return fmt.Errorf("InsertRecordToTable Error: %q. %s",resp.Status, message)
	} else {
		if message[0] != '1' {
			return fmt.Errorf("Teams Body Error: %q", string(message))
		}
		utils.Debug("Response body: %q\n", message)
	}
	return nil
}
