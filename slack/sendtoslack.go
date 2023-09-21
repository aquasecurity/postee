package slack_api

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func SendToUrl(url string, data []byte) error {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	r := bytes.NewReader(data)
	resp, err := client.Post(url, "application/json", r)
	if err != nil {
		log.Printf("Slack API error: %v", err)
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
