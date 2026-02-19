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
// instanceURL is the ServiceNow instance root URL (e.g. "https://ven05031.service-now.com/" or "https://fsadev.servicenowservices.com"),
// as provided by the customer; it is not constructed from instance name + baseServer.
func InsertRecordToTable(user, password, instanceURL, table string, content []byte) (*ServiceNowResponse, error) {
	base := strings.TrimSuffix(instanceURL, "/")
	url := base + "/" + baseApiPath + table
	r := bytes.NewReader(content)
	client := http.DefaultClient
	reg, err := http.NewRequest("POST", url, r)
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
