package router_test

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/router"
	"github.com/aquasecurity/postee/v2/routes"
	"github.com/stretchr/testify/assert"

	servicenow "github.com/aquasecurity/postee/v2/servicenow"
)

const (
	msg = `
{
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
	rego = `package example.audit.html
title:="Audit event received"
result:=[{"type":"section","text":{"type":"mrkdwn","text": input.user}}]
`
	want = `[{"text":{"text":"upwork","type":"mrkdwn"},"type":"section"}]`
)

func TestAudit(t *testing.T) {
	received := make(chan ([]byte))

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed ioutil.ReadAll: %s\n", err)
			received <- []byte{}
			return
		}

		received <- body

		defer r.Body.Close()
	}))
	defer ts.Close()

	if err := router.WithNewConfigAndDbPath("test", "test_webhooks.db"); err != nil {
		t.Errorf("Unexpected WithNewConfig error: %v", err)
	}

	err := router.AddTemplate(&data.Template{
		Name: "audit-json-template",
		Body: rego,
	})
	if err != nil {
		t.Logf("Error: %v", err)
		return
	}
	err = router.AddOutput(&data.OutputSettings{
		Name:   "test-webhook",
		Type:   "webhook",
		Enable: true,
		Url:    ts.URL,
	})
	if err != nil {
		return
	}

	router.AddRoute(&routes.InputRoute{
		Name:     "test",
		Outputs:  []string{"test-webhook"},
		Template: "audit-json-template",
	})
	router.Send([]byte(msg))
	defer os.Remove("webhooks.db")
	got := <-received
	assert.Equal(t, string(got), want, "unexpected response")
}

func TestSelectTemplateByInputField(t *testing.T) {
	preinstalledTemplates := map[string]string{
		"raw-json": `package example.rawmessage.json
title:= "Audit raw json event received"
result:= "result of raw-json template"`,
		"vuls-servicenow": `package example.vuls.servicenow
title:= "Audit vuls servicenow event received"
result:= "result of vuls-servicenow template"`,
		"insight-servicenow": `package example.insight.servicenow
title:= "Audit insight servicenow event received"
result:= "result of insight-servicenow template"`,
		"incident-servicenow": `package example.incident.servicenow
title:= "Audit incident servicenow event received"
result:= "result of incident-servicenow template"`,
		"iac-servicenow": `package example.iac.servicenow
title:= "Audit iac servicenow event received"
result:= "result of iac-servicenow template"`,
	}
	tests := []struct {
		name   string
		input  string
		output *data.OutputSettings
		want   string
	}{
		{
			name:   "Select image servicenow",
			input:  `{"custom_trigger_type": "custom-scan_result"}`,
			output: &data.OutputSettings{Name: "test-sn", Type: "serviceNow", Enable: true},
			want:   `{"short_description":"Audit vuls servicenow event received","work_notes":"[code]result of vuls-servicenow template[/code]","opened_at":"","caller_id":"","category":"","subcategory":"","impact":3,"urgency":3,"state":0,"description":"","assigned_to":"","assignment_group":""}`,
		},
		{
			name:   "Select insight servicenow",
			input:  `{"custom_trigger_type": "custom-insight"}`,
			output: &data.OutputSettings{Name: "test-sn", Type: "serviceNow", Enable: true},
			want:   `{"short_description":"Audit insight servicenow event received","work_notes":"[code]result of insight-servicenow template[/code]","opened_at":"","caller_id":"","category":"","subcategory":"","impact":3,"urgency":3,"state":0,"description":"","assigned_to":"","assignment_group":""}`,
		},
		{
			name:   "Select incident servicenow",
			input:  `{"custom_trigger_type": "custom-incident"}`,
			output: &data.OutputSettings{Name: "test-sn", Type: "serviceNow", Enable: true},
			want:   `{"short_description":"Audit incident servicenow event received","work_notes":"[code]result of incident-servicenow template[/code]","opened_at":"","caller_id":"","category":"","subcategory":"","impact":3,"urgency":3,"state":0,"description":"","assigned_to":"","assignment_group":""}`,
		},
		{
			name:   "Select incident servicenow",
			input:  `{"custom_trigger_type": "custom-iac"}`,
			output: &data.OutputSettings{Name: "test-sn", Type: "serviceNow", Enable: true},
			want:   `{"short_description":"Audit iac servicenow event received","work_notes":"[code]result of iac-servicenow template[/code]","opened_at":"","caller_id":"","category":"","subcategory":"","impact":3,"urgency":3,"state":0,"description":"","assigned_to":"","assignment_group":""}`,
		},
		{
			name:   "Select incident jira",
			input:  `{"custom_trigger_type": "custom-incident"}`,
			output: &data.OutputSettings{Name: "test-sn", Type: "jira", Enable: true},
			want:   `{"short_description":"Audit raw json event received","work_notes":"[code]result of raw-json template[/code]","opened_at":"","caller_id":"","category":"","subcategory":"","impact":3,"urgency":3,"state":0,"description":"","assigned_to":"","assignment_group":""}`,
		},
		{
			name:   "Select template without 'custom_trigger_type' field",
			input:  ``,
			output: &data.OutputSettings{Name: "test-sn", Type: "jira", Enable: true},
			want:   `{"short_description":"Audit raw json event received","work_notes":"[code]result of raw-json template[/code]","opened_at":"","caller_id":"","category":"","subcategory":"","impact":3,"urgency":3,"state":0,"description":"","assigned_to":"","assignment_group":""}`,
		},
	}
	received := make(chan ([]byte))

	if err := router.WithNewConfigAndDbPath("test", "test_webhooks.db"); err != nil {
		t.Errorf("Unexpected WithNewConfig error: %v", err)
	}

	// overwrite InsertRecordToTable function for this test
	savedInsertRecordToTable := servicenow.InsertRecordToTable
	servicenow.InsertRecordToTable = func(user, password, instance, table string, content []byte) (*servicenow.ServiceNowResponse, error) {
		received <- content
		return &servicenow.ServiceNowResponse{ServiceNowResult: servicenow.ServiceNowResult{SysID: "testSysID"}}, nil
	}
	defer func() { servicenow.InsertRecordToTable = savedInsertRecordToTable }()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for n, r := range preinstalledTemplates {
				err := router.AddTemplate(&data.Template{
					Name: n,
					Body: r,
				})
				if err != nil {
					t.Logf("Error: %v", err)
					return
				}
			}

			err := router.AddOutput(tt.output)
			if err != nil {
				return
			}

			router.AddRoute(&routes.InputRoute{
				Name:     "test",
				Outputs:  []string{tt.output.Name},
				Template: "raw-json",
			})
			router.Send([]byte(tt.input))
			defer os.Remove("webhooks.db")
			got := <-received
			assert.Equal(t, tt.want, string(got), "unexpected response")
		})
	}

}

func TestConcurrentSafe(t *testing.T) {
	received := make(chan ([]byte), 1000)
	done := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed ioutil.ReadAll: %s\n", err)
			received <- []byte{}
			return
		}

		received <- body
		r.Body.Close()
		if len(received) == 100 {
			close(done)
		}

	}))
	defer ts.Close()
	defer close(received)

	if err := router.New(); err != nil {
		t.Errorf("Unexpected New error: %v", err)
	}

	err := router.AddTemplate(&data.Template{
		Name: "audit-json-template",
		Body: rego,
	})
	if err != nil {
		t.Logf("Error AddTemplate: %v", err)
		return
	}
	err = router.AddOutput(&data.OutputSettings{
		Name:   "test-webhook",
		Type:   "webhook",
		Enable: true,
		Url:    ts.URL,
	})
	if err != nil {
		t.Logf("Error AddOutput: %v", err)
		return
	}

	router.AddRoute(&routes.InputRoute{
		Name:     "test",
		Outputs:  []string{"test-webhook"},
		Template: "audit-json-template",
	})

	go addRoutes(done)
	go addTemplates(done)
	go addOutputs(done)
	go updateOutputs(done)
	go addCallbacks(done)
	go deleteTemplates(done)
	time.Sleep(50 * time.Millisecond)
	for i := 0; i < 100; i++ {
		router.Send([]byte(msg))
		time.Sleep(500 * time.Microsecond)
	}

	<-done
	time.Sleep(50 * time.Millisecond)
}

func addTemplates(done <-chan struct{}) {
	ticker := time.NewTicker(time.Millisecond)
	count := 0
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			_ = router.AddTemplate(&data.Template{
				Name: "audit-json-template" + fmt.Sprint(count),
				Body: rego,
			})

		}
		count++
	}
}

func deleteTemplates(done <-chan struct{}) {
	ticker := time.NewTicker(time.Millisecond)
	count := 0
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			_ = router.DeleteTemplate("audit-json-template" + fmt.Sprint(count))

		}
		count++
	}
}

func addRoutes(done <-chan struct{}) {
	ticker := time.NewTicker(time.Millisecond)
	count := 0
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			router.AddRoute(&routes.InputRoute{
				Name:     "test" + fmt.Sprint(count),
				Outputs:  []string{"none"},
				Template: "audit-json-template",
			})

		}
		count++
	}
}

func addOutputs(done <-chan struct{}) {
	ticker := time.NewTicker(time.Millisecond)
	count := 0
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			_ = router.AddOutput(&data.OutputSettings{
				Name:   "stdout" + fmt.Sprint(count),
				Type:   "stdout",
				Enable: true,
			})

		}
		count++
	}
}

func updateOutputs(done <-chan struct{}) {
	ticker := time.NewTicker(time.Millisecond)
	count := 0
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			_ = router.UpdateOutput(&data.OutputSettings{
				Name:   "stdout" + fmt.Sprint(count),
				Type:   "stdout",
				Enable: true,
			})

		}
		count++
	}
}

func addCallbacks(done <-chan struct{}) {
	ticker := time.NewTicker(time.Millisecond)
	count := 0
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			router.SetInputCallbackFunc(fmt.Sprint(count), func(inputMessage map[string]interface{}) bool {
				return true
			})
		}
		count++
	}
}
