package outputs

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/aquasecurity/postee/formatting"
	"github.com/aquasecurity/postee/layout"
)

type NexusIqOutput struct {
	Name           string
	Url            string
	User           string
	Password       string
	OrganizationId string
}

func (nexus *NexusIqOutput) GetName() string {
	return nexus.Name
}

func (nexus *NexusIqOutput) Init() error {
	/*TODO*/
	return nil
}

func (nexus *NexusIqOutput) createOrGetApp(appName string) (string, error) {
	/* TODO */
	return "da7dd0ae62da4cc6a9adeb168f9a6099", nil
}

func (nexus *NexusIqOutput) Send(content map[string]string) error {
	appId, err := nexus.createOrGetApp(content["title"])

	if err != nil {
		log.Printf("Can't register application: %v", err)
		return err
	}

	url := fmt.Sprintf("%s/api/v2/scan/applications/%s/sources/cyclone", nexus.Url, appId)

	log.Printf("Sending components payload to Nexus IQ (%q)...", nexus.Url)

	data := content["description"]

	log.Printf("%s\n", data)

	client := http.DefaultClient
	req, err := http.NewRequest("POST", url, strings.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/xml")
	req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(nexus.User+":"+nexus.Password)))

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error when calling nexus: %v", err)
		return err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Unable to call Nexus API %q Error: %v", nexus.Name, err)
		return err
	}

	if resp.StatusCode > 399 {
		msg := "received incorrect response status: %d. Body: %s"
		log.Printf(msg, resp.StatusCode, body)
		return fmt.Errorf(msg, resp.StatusCode, body)
	}
	return nil
}

func (nexus *NexusIqOutput) Terminate() error {
	/*TODO*/
	return nil
}

func (nexus *NexusIqOutput) GetLayoutProvider() layout.LayoutProvider {
	/*TODO come up with smaller interface that doesn't include GetLayoutProvider()*/
	return new(formatting.HtmlProvider)
}
