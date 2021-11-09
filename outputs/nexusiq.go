package outputs

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/aquasecurity/postee/formatting"
	"github.com/aquasecurity/postee/layout"
)

var notAllowed = regexp.MustCompile(`[\.:]`)

func sanitizedAppName(appName string) string {
	return notAllowed.ReplaceAllString(appName, "_")
}

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
func (nexus *NexusIqOutput) auth() string {
	return base64.StdEncoding.EncodeToString([]byte(nexus.User + ":" + nexus.Password))
}

func (nexus *NexusIqOutput) execute(method string, url string, payload string, headers map[string]string) (map[string]interface{}, error) {
	fmt.Println(url)

	client := http.DefaultClient

	var reader io.Reader = nil

	if payload != "" {
		reader = strings.NewReader(payload)
	}

	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return nil, err
	}
	for name, value := range headers {
		req.Header.Add(name, value)

	}
	req.Header.Add("Authorization", "Basic "+nexus.auth())

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	fmt.Println(string(body))

	if resp.StatusCode > 399 { //TODO better check
		msg := "received incorrect response status: %d. Body: %s"
		return nil, fmt.Errorf(msg, resp.StatusCode, body)
	}

	r := make(map[string]interface{})

	err = json.Unmarshal([]byte(body), &r)

	if err != nil {
		return nil, err
	}

	return r, nil

}

func (nexus *NexusIqOutput) getAppByNameAndOrg(organizationId string, appName string) (string, error) {
	sanitizedAppName := sanitizedAppName(appName)
	url := fmt.Sprintf("%s/api/v2/applications/organization/%s", nexus.Url, organizationId)
	r, err := nexus.execute("GET", url, "", map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return "", err
	}
	applications := r["applications"].([]interface{})
	for _, item := range applications {
		app := item.(map[string]interface{})
		if app["publicId"].(string) == sanitizedAppName {
			return app["id"].(string), nil
		}
	}
	return "", nil
}
func (nexus *NexusIqOutput) createApp(organizationId string, appName string) (string, error) {
	sanitizedAppName := sanitizedAppName(appName)
	payload := map[string]string{
		"publicId":       sanitizedAppName,
		"name":           sanitizedAppName,
		"organizationId": organizationId,
	}

	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/api/v2/applications", nexus.Url)

	r, err := nexus.execute("POST", url, string(b), map[string]string{"Content-Type": "application/json"})

	if err != nil {
		return "", err
	}

	return r["id"].(string), nil
}

func (nexus *NexusIqOutput) createOrGetApp(appName string) (string, error) {
	fmt.Printf("get app for name: %s\n", appName)
	app, err := nexus.getAppByNameAndOrg(nexus.OrganizationId, appName)
	if err != nil {
		return "", err
	}
	if app == "" {
		fmt.Printf("create app for name: %s\n", appName)
		app, err = nexus.createApp(nexus.OrganizationId, appName)
		if err != nil {
			return "", err
		}
	}
	return app, nil
}
func (nexus *NexusIqOutput) registerBom(appId string, bom string) error {
	url := fmt.Sprintf("%s/api/v2/scan/applications/%s/sources/cyclone", nexus.Url, appId)

	_, err := nexus.execute("POST", url, string(bom), map[string]string{"Content-Type": "application/xml"})

	if err != nil {
		return err
	}
	return nil
}

func (nexus *NexusIqOutput) Send(content map[string]string) error {
	appId, err := nexus.createOrGetApp(content["title"])

	fmt.Printf("get app id %s\n", appId)

	if err != nil {
		return err
	}

	data := content["description"]

	log.Printf("%s\n", data)

	err = nexus.registerBom(appId, data)
	if err != nil {
		return err
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
