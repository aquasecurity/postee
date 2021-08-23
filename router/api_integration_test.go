package router_test

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aquasecurity/postee/data"
	"github.com/aquasecurity/postee/router"
	"github.com/aquasecurity/postee/routes"
	"github.com/stretchr/testify/assert"
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

	router.WithNewConfig("test", "./webhook.db")

	err := router.AddTemplate(&data.Template{
		Name: "audit-json-template",
		Body: rego,
	})
	if err != nil {
		t.Logf("Error: %v", err)
		return
	}
	router.AddOutput(&data.OutputSettings{
		Name:   "test-webhook",
		Type:   "webhook",
		Enable: true,
		Url:    ts.URL,
	})

	router.AddRoute(&routes.InputRoute{
		Name:     "test",
		Outputs:  []string{"test-webhook"},
		Template: "audit-json-template",
		Plugins: routes.Plugins{
			PolicyShowAll: true,
		},
	})
	router.Send([]byte(msg))
	got := <-received
	assert.Equal(t, string(got), want, "unexpected response")
}
