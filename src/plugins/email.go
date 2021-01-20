package plugins

import (
	"fmt"
	"formatting"
	"github.com/pkg/errors"
	"layout"
	"log"
	"net"
	"net/smtp"
	"settings"
	"strings"
)

const (
	ApplicationScopeOwner = "<%application_scope_owner%>"
)

var (
	errThereIsNoRecipient = errors.New("there is no recipient")
)

type EmailPlugin struct{
	User       string
	Password   string
	Host       string
	Port       string
	Sender     string
	Recipients []string
	UseMX 	   bool
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
	recipients := []string{}
	for _, r := range email.Recipients {
		if r == ApplicationScopeOwner {
			ownersIn, ok := content["owners"]
			if !ok {
				log.Printf("%q issue: recipients field contains %q, but received a webhook without this data",
				email.EmailSettings.PluginName, ApplicationScopeOwner)
				continue
			}
			for _, o := range strings.Split(ownersIn, ";") {
				if o != "" { recipients = append(recipients, o) }
			}
		} else {
			recipients = append(recipients, r)
		}
	}
	if len(recipients) == 0 {
		return errThereIsNoRecipient
	}

	if email.UseMX {
		sendViaMxServers(email.Sender, subject, body, recipients)
		return nil
	}

	msg := fmt.Sprintf(
		"To: %s\r\n"+
		"From: %s\r\n" +
			"Subject: %s\r\n"+
				"Content-Type: text/html; charset=UTF-8\r\n\r\n%s\r\n",
			strings.Join(recipients,","), email.Sender, subject, body)

		auth := smtp.PlainAuth("", email.User, email.Password, email.Host)
		err := smtp.SendMail(email.Host+":"+email.Port, auth, email.Sender, recipients, []byte(msg))
		if err != nil {
			log.Println("SendMail Error:", err)
			log.Printf("From: %q, to %v via %q", email.Sender, email.Recipients, email.Host)
			return err
		}
	log.Println("Email was sent successfully!")
	return nil
}

func sendViaMxServers(from, subj, msg string, recipients []string) {
	for _, rcpt := range recipients {
		at := strings.LastIndex(rcpt, "@")
		if at < 0 {
			log.Printf("%q isn't email", rcpt)
			continue
		}
		host := rcpt[at+1:]
		mxs, err := net.LookupMX(host)
		if err != nil {
			log.Print(err)
			continue
		}
		for _, mx := range mxs {
			message := fmt.Sprintf(
				"To: %s\r\n"+
					"From: %s\r\n" +
					"Subject: %s\r\n"+
					"Content-Type: text/html; charset=UTF-8\r\n\r\n%s\r\n", rcpt, from, subj, msg)

			if err := smtp.SendMail(mx.Host+":25", nil, from, []string{rcpt}, []byte(message)); err != nil {
				log.Printf("SendMail error to %q via %q", rcpt, mx.Host)
				log.Print(err)
				continue
			}
			log.Printf("The message to %q was sent succesful via %q!", rcpt, mx.Host)
			break
		}
	}
}