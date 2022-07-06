package outputs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/formatting"
	"github.com/aquasecurity/postee/v2/layout"
	"github.com/aquasecurity/postee/v2/log"
)

const (
	defaultSizeLimit = 10000
	SplunkType       = "splunk"
)

type SplunkOutput struct {
	Name         string
	Url          string
	Token        string
	EventLimit   int
	splunkLayout layout.LayoutProvider
}

func (splunk *SplunkOutput) GetType() string {
	return SplunkType
}

func (splunk *SplunkOutput) GetName() string {
	return splunk.Name
}

func (splunk *SplunkOutput) CloneSettings() *data.OutputSettings {
	return &data.OutputSettings{
		Name:      splunk.Name,
		Url:       splunk.Url,
		Token:     splunk.Token,
		SizeLimit: splunk.EventLimit,
		Enable:    true,
		Type:      SplunkType,
	}
}

func (splunk *SplunkOutput) Init() error {
	splunk.splunkLayout = new(formatting.HtmlProvider)
	log.Logger.Infof("Successfully initialized Splunk output %q", splunk.Name)
	return nil
}

func (splunk *SplunkOutput) Send(input map[string]string) (string, error) {
	log.Logger.Infof("Sending to Splunk via %q", splunk.Name)

	if splunk.EventLimit == 0 {
		splunk.EventLimit = defaultSizeLimit
	}
	if splunk.EventLimit < defaultSizeLimit {
		log.Logger.Warnf("%q has a short limit %d (default %d)",
			splunk.Name, splunk.EventLimit, defaultSizeLimit)
	}

	if !strings.HasSuffix(splunk.Url, "/") {
		splunk.Url += "/"
	}

	rawEventData, ok := input["description"]
	if !ok {
		log.Logger.Error("Splunk sending error: empty content")
		return EmptyID, nil
	}

	eventData := make(map[string]interface{})
	err := json.Unmarshal([]byte(rawEventData), &eventData)
	if err != nil {
		log.Logger.Errorf("sending to Splunk %q error: %v", splunk.Name, err)
		return EmptyID, err
	}

	eventFormat := "{\"sourcetype\": \"_json\", \"event\": "
	constLimit := len(eventFormat) - 1

	var rawMsg []byte
	category, ok := eventData[EventCategoryAttribute]
	if ok && category == CategoryIncident {
		rawMsg = []byte(rawEventData)
	} else {
		scanInfo := new(data.ScanImageInfo)
		err := json.Unmarshal([]byte(rawEventData), scanInfo)
		if err != nil {
			log.Logger.Errorf("sending to %q error: %v", splunk.Name, err)
			return EmptyID, err
		}

		for {
			rawMsg, err = json.Marshal(scanInfo)
			if err != nil {
				log.Logger.Errorf("sending to Splunk %q error: %v", splunk.Name, err)
				return EmptyID, err
			}
			if len(rawMsg) < splunk.EventLimit-constLimit {
				break
			}
			switch {
			case len(scanInfo.Resources) > 0:
				scanInfo.Resources = nil
				continue
			case len(scanInfo.Malwares) > 0:
				scanInfo.Malwares = nil
				continue
			case len(scanInfo.SensitiveData) > 0:
				scanInfo.SensitiveData = nil
				continue
			default:
				msg := fmt.Sprintf("Scan result for %q is large for %q , its size if %d (limit %d)",
					scanInfo.Image, splunk.Name, len(rawMsg), splunk.EventLimit)
				log.Logger.Infof(msg)
				return EmptyID, errors.New(msg)
			}
		}
	}

	var buff bytes.Buffer
	buff.WriteString(eventFormat)
	buff.Write(rawMsg)
	buff.WriteByte('}')

	req, err := http.NewRequest("POST", splunk.Url+"services/collector", &buff)
	if err != nil {
		return EmptyID, err
	}

	req.Header.Add("Authorization", "Splunk "+splunk.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return EmptyID, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		b, _ := ioutil.ReadAll(resp.Body)
		log.Logger.Error(fmt.Errorf("splunk sending error: failed response status %q. Body: %q", resp.Status, string(b)))
		return EmptyID, errors.New("failed response status for Splunk sending")
	}
	log.Logger.Debugf("Sending a message to Splunk via %q was successful!", splunk.Name)
	return EmptyID, nil
}

func (splunk *SplunkOutput) Terminate() error {
	log.Logger.Infof("Splunk output %q terminated", splunk.Name)
	return nil
}

func (splunk *SplunkOutput) GetLayoutProvider() layout.LayoutProvider {
	return splunk.splunkLayout
}
