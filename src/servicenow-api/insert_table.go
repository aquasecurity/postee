package servicenow_api

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
)

func InsertRecordToTable(user, password, instance, table, content string) error  {
	url := fmt.Sprintf("https://%s.%s%s%s%s",
		instance, BaseServer, baseApiUrl,tableApi, table)
	r := bytes.NewReader([]byte(content))
	client := http.DefaultClient
	reg, err := http.NewRequest("POST", url, r)
	if err != nil { return err}
	reg.Header.Add("Content-Type", "application/json")
	reg.Header.Add("Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password)))
	resp, err := client.Do(reg)
	if err != nil {		return err	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("InsertRecordToTable Error: %v\nHeader: %v", resp.Status, resp.Header)
	}
	return nil
}

