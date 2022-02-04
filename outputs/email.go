package outputs

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"strconv"
	"strings"

	"github.com/aquasecurity/postee/v2/formatting"
	"github.com/aquasecurity/postee/v2/layout"
)

var (
	errThereIsNoRecipient = errors.New("there is no recipient")
	lookupMXFunc          = net.LookupMX
)

type EmailOutput struct {
	Name       string
	User       string
	Password   string
	Host       string
	Port       int
	Sender     string
	Recipients []string
	UseMX      bool
	sendFunc   func(addr string, a smtp.Auth, from string, to []string, msg []byte) error
}

func (email *EmailOutput) GetName() string {
	return email.Name
}

func (email *EmailOutput) Init() error {
	log.Printf("Starting Email output %q...", email.Name)
	if email.Sender == "" {
		email.Sender = email.User
	}

	email.sendFunc = smtp.SendMail
	return nil
}

func (email *EmailOutput) Terminate() error {
	log.Printf("Email output terminated\n")
	return nil
}

func (email *EmailOutput) GetLayoutProvider() layout.LayoutProvider {
	return new(formatting.HtmlProvider)
}

func (email *EmailOutput) Send(content map[string]string) error {
	subject := content["title"]
	body := content["description"]
	port := strconv.Itoa(email.Port)
	recipients := getHandledRecipients(email.Recipients, &content, email.Name)
	if len(recipients) == 0 {
		return errThereIsNoRecipient
	}

	msg := fmt.Sprintf(
		"To: %s\r\n"+
			"From: %s\r\n"+
			"Subject: %s\r\n"+
			"Content-Type: text/html; charset=UTF-8\r\n\r\n%s\r\n",
		strings.Join(recipients, ","), email.Sender, subject, body)

	if email.UseMX {
		email.sendViaMxServers(port, msg, recipients)
		return nil
	}

	var auth smtp.Auth
	if len(email.Password) > 0 && len(email.User) > 0 {
		auth = smtp.PlainAuth("", email.User, email.Password, email.Host)
	}

	err := email.sendFunc(email.Host+":"+port, auth, email.Sender, recipients, []byte(msg))
	if err != nil {
		log.Println("SendMail Error:", err)
		log.Printf("From: %q, to %v via %q", email.Sender, email.Recipients, email.Host)
		return err
	}
	log.Println("Email was sent successfully!")
	return nil
}

func (email EmailOutput) sendViaMxServers(port string, msg string, recipients []string) {
	for _, rcpt := range recipients {
		at := strings.LastIndex(rcpt, "@")
		if at < 0 {
			log.Printf("%q isn't email", rcpt)
			continue
		}

		host := rcpt[at+1:]
		mxs, err := lookupMXFunc(host)
		if err != nil {
			log.Println("error looking up mx host: ", err)
			continue
		}

		for _, mx := range mxs {
			if err := email.sendFunc(mx.Host+":"+port, nil, email.Sender, recipients, []byte(msg)); err != nil {
				log.Printf("SendMail error to %q via %q", rcpt, mx.Host)
				log.Println("error: ", err)
				continue
			}
			log.Printf("The message to %q was sent successful via %q!", rcpt, mx.Host)
			break
		}
	}
}
