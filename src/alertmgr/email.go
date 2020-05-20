package alertmgr

import (
	"fmt"
	"formatting"
	"layout"
	"log"
	"net/smtp"
	"strings"
)

type EmailPlugin struct{
	user string
	password string
	host string
	port string
	sender string
	recipients []string
}

func NewEmailPlugin(settings PluginSettings) *EmailPlugin {
	em := new(EmailPlugin)
	em.user = settings.User
	em.password = settings.Password
	em.host = settings.Host
	em.port = settings.Port
	em.recipients = settings.Recipients
	em.sender = settings.Sender
	return em
}

func (email *EmailPlugin) Init() error {
	log.Printf("Starting Email plugin....")
	if email.sender == "" {
		email.sender = email.user
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
		strings.Join(email.recipients,","), email.sender, subject, body)
	auth := smtp.PlainAuth("", email.user, email.password, email.host)
	err := smtp.SendMail(email.host+":"+email.port, auth, email.sender, email.recipients, []byte(msg))
	if err != nil {
		log.Println("Error", err)
		return err
	}
	log.Println("Email was sent successfully!")
	return nil
}
