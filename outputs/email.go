package outputs

import (
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"

	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/formatting"
	"github.com/aquasecurity/postee/v2/layout"
	"github.com/aquasecurity/postee/v2/log"
)

const (
	EmailType = "email"
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

func (email *EmailOutput) GetType() string {
	return EmailType
}

func (email *EmailOutput) GetName() string {
	return email.Name
}

func (email *EmailOutput) CloneSettings() *data.OutputSettings {
	return &data.OutputSettings{
		Name: email.Name,
		User: email.User,
		//password is omitted
		Host:       email.Host,
		Port:       email.Port,
		Sender:     email.Sender,
		UseMX:      email.UseMX,
		Recipients: data.CopyStringArray(email.Recipients),
		Enable:     true,
		Type:       EmailType,
	}
}

func (email *EmailOutput) Init() error {
	if email.Sender == "" {
		email.Sender = email.User
	}

	email.sendFunc = smtp.SendMail

	log.Logger.Infof("Successfully initialized email output %s", email.Name)
	return nil
}

func (email *EmailOutput) Terminate() error {
	log.Logger.Debug("Email output terminated")
	return nil
}

func (email *EmailOutput) GetLayoutProvider() layout.LayoutProvider {
	return new(formatting.HtmlProvider)
}

func (email *EmailOutput) Send(content map[string]string) (string, error) {
	log.Logger.Infof("Sending to email via %q", email.Name)
	subject := content["title"]
	body := content["description"]
	port := strconv.Itoa(email.Port)
	recipients := getHandledRecipients(email.Recipients, &content, email.Name)
	if len(recipients) == 0 {
		return EmptyID, errThereIsNoRecipient
	}

	msg := fmt.Sprintf(
		"To: %s\r\n"+
			"From: %s\r\n"+
			"Subject: %s\r\n"+
			"Content-Type: text/html; charset=UTF-8\r\n\r\n%s\r\n",
		strings.Join(recipients, ","), email.Sender, subject, body)

	if email.UseMX {
		email.sendViaMxServers(port, msg, recipients)
		return EmptyID, nil
	}

	var auth smtp.Auth
	if len(email.Password) > 0 && len(email.User) > 0 {
		auth = smtp.PlainAuth("", email.User, email.Password, email.Host)
	}

	err := email.sendFunc(email.Host+":"+port, auth, email.Sender, recipients, []byte(msg))
	if err != nil {
		log.Logger.Errorf("failed to send email: %v", err)
		log.Logger.Debugf("failed to send email from: %q, to %v via %q:%d", email.Sender, email.Recipients, email.Host, email.Port)
		return EmptyID, err
	}
	log.Logger.Debug("Email was sent successfully!")
	return EmptyID, nil
}

func (email EmailOutput) sendViaMxServers(port string, msg string, recipients []string) {
	for _, rcpt := range recipients {
		at := strings.LastIndex(rcpt, "@")
		if at < 0 {
			log.Logger.Error(fmt.Errorf("%q isn't valid email", rcpt))
			continue
		}

		host := rcpt[at+1:]
		mxs, err := lookupMXFunc(host)
		if err != nil {
			log.Logger.Error(fmt.Errorf("error looking up mx host: %w", err))
			continue
		}

		for _, mx := range mxs {
			if err := email.sendFunc(mx.Host+":"+port, nil, email.Sender, recipients, []byte(msg)); err != nil {
				log.Logger.Error(fmt.Errorf("sendMail error to %q via %q. Error: %w", rcpt, mx.Host, err))
				continue
			}
			log.Logger.Debugf("The message to %q was sent successful via %q!", rcpt, mx.Host)
			break
		}
	}
}
