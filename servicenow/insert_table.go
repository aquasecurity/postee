package servicenow_api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/aquasecurity/postee/v2/utils"
)

var InsertRecordToTable = func(user, password, instance, table string, content []byte) (*ServiceNowResponse, error) {
	url := fmt.Sprintf("https://%s.%s%s%s%s",
		instance, BaseServer, baseApiUrl, tableApi, table)
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
