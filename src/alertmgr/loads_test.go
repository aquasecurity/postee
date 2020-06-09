package alertmgr

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestLoads(t *testing.T) {
	cfgData := `
---
- name: jira
  type: jira
  enable: true
  url: "http://localhost:2990/jira"
  user: admin
  password: admin
  tls_verify: false
  project_key: KEY
  description:
  summary:
  issuetype: "Bug"
  priority: Medium
  assignee: 
  Policy-Min-Vulnerability: Critical
  labels: ["label1", "label2"]
  Policy-Min-Vulnerability: high

- name: my-slack
  type: slack
  enable: true
  url: "https://hooks.slack.com/services/TT/BBB/WWWW"

- name: email
  type: email
  enable: true
  user: EMAILUSER
  password: EMAILPASS
  host: smtp.gmail.com
  port: 587
  recipients: ["demo@gmail.com"]

- name: my-servicenow
  type: serviceNow
  enable: true
  user: SERVICENOWUSER
  password: SERVICENOWPASS
  instance: dev00000
  board: incident
`
	cfgName :="cfg_test.yaml"
	ioutil.WriteFile(cfgName, []byte(cfgData),0644)
	defer func() {
		os.Remove(cfgName)
	}()

	demoCtx := Instance()
	demoCtx.Start(cfgName)
	if len(demoCtx.plugins) != 4 {
		t.Errorf("There are stopped plugins\nWaited: %d\nResult: %d", 4, len(demoCtx.plugins))
	}

	_, ok := demoCtx.plugins["my-servicenow"]
	if !ok {
		t.Errorf("Plugin 'my-servicenow' didn't run!")
	}
}
