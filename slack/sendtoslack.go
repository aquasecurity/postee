package slack_api

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/aquasecurity/postee/v2/log"
)

func SendToUrl(url string, data []byte) error {
	r := bytes.NewReader(data)
	resp, err := http.Post(url, "application/json", r)
	if err != nil {
		log.Logger.Errorf("Slack API error: %v", err)
		return err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		msg, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf("Slack API error: Status: %q. Message: %q",
			resp.Status, msg)
	}
	return nil
}
