package eventservice

import (
	"github.com/aquasecurity/postee/plugins"
	"github.com/aquasecurity/postee/settings"
	"os"
	"testing"
	"time"
)

const demoRego = `package postee
default allow = false
allow {
    contains(input.action, "Login")
}
`

const demoRegoCorrectEvent = `{
  "action": "Login",
  "adjective": "demolab.aquasec.com",
  "category": "User",
  "date": 1618409998039,
  "description": "Roles: Administrator",
  "id": 0,
  "result": 1,
  "source_ip": "172.18.0.9",
  "time": 1618409998,
  "type": "Administration",
  "user": "upwork"
}`
const demoRegoFailedEvent = `{
  "action": "Update Log Management",
  "adjective": "WebHook",
  "category": "Integration",
  "date": 1618468595104,
  "id": 0,
  "result": 1,
  "time": 1618468595,
  "type": "Administration",
  "user": "upwork"
}`

func TestHandlingRego(t *testing.T) {
	const demoRegoFileName = "demo.rego"
	f, err := os.Create(demoRegoFileName)
	if err != nil {
		panic(err)
	}
	f.WriteString(demoRego)
	f.Close()
	defer os.RemoveAll(demoRegoFileName)

	demoPlugin := &demoEventPlugin{}
	demoPlugin.settings = &settings.Settings{
		PolicyOPA:               []string{demoRegoFileName},
	}
	plgns := make(map[string]plugins.Plugin)
	plgns["demoEventPlugin"] = demoPlugin
	evntsrvs := &EventService{}


	tests := []struct{
		input string
		isCorrect bool
		shouldRemove bool
	}{
		{demoRegoCorrectEvent, true, false},
		{demoRegoFailedEvent, false, false},
		{"broken input", false, false},
		{demoRegoCorrectEvent, false, true},
	}

	for _, test := range tests {
		if test.shouldRemove {
			os.RemoveAll(demoRegoFileName)
		}
		demoPlugin.resetSending()
		evntsrvs.ResultHandling(test.input, plgns)
		time.Sleep(200*time.Millisecond)
		if demoPlugin.isSent() != test.isCorrect {
			t.Errorf("evntsrvs.ResultHandling(%q) was sent: %T, wanted %T", test.input, demoPlugin.wasSend, test.isCorrect)
		}
	}
}
