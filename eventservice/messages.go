package eventservice

import (
	"bytes"
	"strings"
	"text/template"
)

func GetMessage(event *WebhookEvent) string {
	action := strings.ToLower(event.Action)
	switch action {
	case loginAction:
		return renderLoginTemplate(&loginData{
			IP:   event.SourceIP,
			User: event.User,
		})
	default:
		return renderDefaultTemplate(&defaultData{
			User:   event.User,
			IP:     event.SourceIP,
			Action: action,
		})
	}
}

func renderTemplate(name, base string, data interface{}) string {
	t := template.Must(template.New(name).Parse(base))
	var buffer bytes.Buffer
	t.Execute(&buffer, data)
	return buffer.String()
}

const loginAction = "login"
const loginTemplate = `User {{ .User }} performed login from IP {{ .IP }}`

type loginData struct {
	IP   string
	User string
}

func renderLoginTemplate(data *loginData) string {
	return renderTemplate("loginTemplate", loginTemplate, data)
}

type defaultData struct {
	User   string
	IP     string
	Action string
}

const defaultTemplate = `User {{ .User }}
{{if .IP}}
from IP {{ .IP}}
{{end}}
did {{ .Acton }}
`

func renderDefaultTemplate(data *defaultData) string {
	return renderTemplate("defaultTemplate", defaultTemplate, data)
}
