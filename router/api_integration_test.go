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
