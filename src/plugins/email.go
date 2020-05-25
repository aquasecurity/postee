package plugins

import (
	"fmt"
	"formatting"
	"layout"
	"log"
	"net/smtp"
	"settings"
	"strings"
)

type EmailPlugin struct{
	User       string
	Password   string
	Host       string
	Port       string
	Sender     string
	Recipients []string
	EmailSettings *settings.Settings
}

func (email *EmailPlugin) GetSettings() *settings.Settings {
	return email.EmailSettings
}

func (email *EmailPlugin) Init() error {
	log.Printf("Starting Email plugin %q...", email.EmailSettings.PluginName)
	if email.Sender == "" {
		email.Sender = email.User
	}
	return nil
}

func (email *EmailPlugin) Terminate() error {
	log.Printf("Email plugin terminated\n")
	return nil
}

func (email *EmailPlugin) GetLayoutProvider() layout.LayoutProvider {
	return new(formatting.HtmlProvider)
}

func (email *EmailPlugin) Send(content map[string]string) error {
	subject := content["title"]
	body := content["description"]

	msg := fmt.Sprintf(
		"To: %s\r\n"+
			"From: %s\r\n" +
			"Subject: %s\r\n"+
			"Content-Type: text/html; charset=UTF-8\r\n\r\n%s\r\n",
		strings.Join(email.Recipients,","), email.Sender, subject, body)
	auth := smtp.PlainAuth("", email.User, email.Password, email.Host)
	err := smtp.SendMail(email.Host+":"+email.Port, auth, email.Sender, email.Recipients, []byte(msg))
	if err != nil {
		log.Println("SendMail Error:", err)
		log.Printf("From: %q, to %v via %q", email.Sender, email.Recipients, email.Host)
		return err
	}
	log.Println("Email was sent successfully!")
	return nil
}
