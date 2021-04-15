package eventservice

import (
	"bytes"
	"encoding/json"
	"github.com/aquasecurity/postee/formatting"
	"github.com/aquasecurity/postee/layout"
	"testing"
	"text/template"
)

const correctLoginJson = `{
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

func TestRenderingContent(t *testing.T) {
	correctLoginEvent := &WebhookEvent{}
	if err := json.Unmarshal([]byte(correctLoginJson), correctLoginEvent); err != nil {
		panic(err)
	}
	templ := template.Must(template.New("login").Parse(loginTemplate))
	var loginDescr bytes.Buffer
	loginDescr.WriteString("<p>")
	templ.Execute(&loginDescr, &loginData{
		IP:   "172.18.0.9",
		User: "upwork",
	})
	loginDescr.WriteString("</p>\n")

	tests := []struct {
		data        *WebhookEvent
		provider    layout.LayoutProvider
		title       string
		description string
	}{
		{
			correctLoginEvent,
			new(formatting.HtmlProvider),
			"Administration event",
			loginDescr.String(),
		},
	}

	for _, test := range tests {
		title, descr := buildTitleAndDescription(test.provider, test.data)
		if title != test.title {
			t.Errorf("buildTitleAndDescription(%v) title == %q, wanted %q", test.data, title, test.title)
		}
		if descr != test.description {
			t.Errorf("buildTitleAndDescription(%v) description == %q, wanted %q", test.data, descr, test.description)
		}
	}
}

func TestBuildMapContent(t *testing.T) {
	title := "Title"
	descr := "Description"
	mp := buildMapContent(title, descr)
	titleIn, ok := mp["title"]
	if !ok {
		t.Errorf("buildMapContent(%q, %q) doesn't return an important field `title`", title, descr)
	}
	if titleIn != title {
		t.Errorf("buildMapContent(%q, %q) title == %q", title, descr, titleIn)

	}
	d, ok := mp["description"]
	if !ok {
		t.Errorf("buildMapContent(%q, %q) doesn't return an important field `description`", title, descr)
	}
	if d != descr {
		t.Errorf("buildMapContent(%q, %q) description == %q", title, descr, d)
	}
}
