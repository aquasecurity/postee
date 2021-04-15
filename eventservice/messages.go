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
	}
	return ""
}

const loginAction = "login"

const loginTemplate = `User {{ .User }} performed login from IP {{ .IP }}`

type loginData struct {
	IP   string
	User string
}

func renderLoginTemplate(data *loginData) string {
	t := template.Must(template.New("login").Parse(loginTemplate))
	var buffer bytes.Buffer
	t.Execute(&buffer, data)
	return buffer.String()
}
