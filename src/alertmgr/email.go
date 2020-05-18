package alertmgr

import (
	"fmt"
	"htmlformatting"
	"log"
	"net/smtp"
	"scanservice"
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

func (email *EmailPlugin) Send(service *scanservice.ScanService) error {
	content := service.GetBody(new(htmlformatting.HtmlProvider))
	subject := service.GetHead()

	msg := fmt.Sprintf(
		"To: %s\r\nSubject: %s\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s\r\n",
		email.recipients[0], subject, content)
	auth := smtp.PlainAuth("", email.user, email.password, email.host)
	err := smtp.SendMail(email.host+":"+email.port, auth, email.sender, email.recipients, []byte(msg))
	if err != nil {
		log.Println("Error", err)
		return err
	}
	fmt.Println("Email was sent successfully!")
	return nil
}
