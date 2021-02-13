package plugins

import (
	"bytes"
	"data"
	"encoding/json"
	"errors"
	"fmt"
	"formatting"
	"io/ioutil"
	"layout"
	"log"
	"net/http"
	"settings"
	"strings"
)

type SplunkPlugin struct {
	Url            string
	Token          string
	SplunkSettings *settings.Settings
	splunkLayout   layout.LayoutProvider
}

func (splunk *SplunkPlugin) Init() error {
	splunk.splunkLayout = new(formatting.HtmlProvider)
	log.Printf("Starting Splunk plugin %q....", splunk.SplunkSettings.PluginName)
	return nil
}

func (splunk *SplunkPlugin) Send(d map[string]string) error {
	log.Printf("Sending a message to %q", splunk.SplunkSettings.PluginName)

	if !strings.HasSuffix(splunk.Url, "/") {
		splunk.Url += "/"
	}

	scanInfo := new(data.ScanImageInfo)
	err := json.Unmarshal([]byte(d["src"]), scanInfo)
	if err != nil {
		log.Printf("sending to %q error: %v", splunk.SplunkSettings.PluginName, err)
		return err
	}
	fields, err := json.Marshal(scanInfo)
	if err != nil {
		log.Printf("sending to %q error: %v", splunk.SplunkSettings.PluginName, err)
		return err
	}

	var buff bytes.Buffer
	fmt.Fprintf(&buff, "{\"sourcetype\": \"_json\", \"event\": ")
	buff.Write(fields)
	buff.WriteByte('}')

	req, err := http.NewRequest("POST", splunk.Url+"services/collector", &buff)
	if err != nil {
		return err
	}

	req.Header.Add("Authorization", "Splunk "+splunk.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		b, _ := ioutil.ReadAll(resp.Body)
		log.Printf("Splunk sending error: failed response status %q. Body: %q", resp.Status, string(b))
		return errors.New("failed response status for Splunk sending")
	}
	log.Printf("Sending a message to %q was successful!", splunk.SplunkSettings.PluginName)
	return nil
}

func (splunk *SplunkPlugin) Terminate() error {
	log.Printf("Splunk plugin %q terminated", splunk.SplunkSettings.PluginName)
	return nil
}

func (splunk *SplunkPlugin) GetLayoutProvider() layout.LayoutProvider {
	return splunk.splunkLayout
}

func (splunk *SplunkPlugin) GetSettings() *settings.Settings {
	return splunk.SplunkSettings
}
