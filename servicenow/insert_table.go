package servicenow_api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/aquasecurity/postee/v2/utils"
)

// InsertRecordToTable posts a record to the given ServiceNow table.
// If instanceURL is non-empty, it is used as the instance root URL (new behaviour; e.g. https://ven05031.service-now.com/ or https://fsadev.servicenowservices.com).
// If instanceURL is empty, the URL is built from instance + BaseServer (legacy behaviour: https://<instance>.service-now.com/).
// At least one of instanceURL or instance must be non-empty.
func InsertRecordToTable(user, password, instanceURL, instance, table string, content []byte) (*ServiceNowResponse, error) {
	if instanceURL == "" && instance == "" {
		return nil, fmt.Errorf("InsertRecordToTable: either url (instance URL) or instance (legacy) must be set")
	}
	var tableURL string
	if instanceURL != "" {
		base := strings.TrimSuffix(instanceURL, "/")
		tableURL = base + "/" + baseApiPath + table
	} else {
		tableURL = fmt.Sprintf("https://%s.%s%s%s", instance, BaseServer, baseApiPath, table)
	}
	r := bytes.NewReader(content)
	client := http.DefaultClient
	reg, err := http.NewRequest("POST", tableURL, r)
	if err != nil {
		return nil, err
	}
	reg.Header.Add("Content-Type", "application/json")
	reg.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+password)))
	resp, err := client.Do(reg)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("InsertRecordToTable Error: %v\nHeader: %v",
			resp.Status, utils.PrnLogResponse(resp.Body))
	}

	responseTicket := new(ServiceNowResponse)
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read the returned data (%w)", err)
	}

	err = json.Unmarshal(data, responseTicket)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshall the data into struct (%w)", err)
	}

	return responseTicket, nil
}
