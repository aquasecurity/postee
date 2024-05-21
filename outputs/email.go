package outputs

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/aws/aws-sdk-go/service/sts"
	"net"
	"strconv"
	"strings"

	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/formatting"
	"github.com/aquasecurity/postee/v2/layout"
	"github.com/aquasecurity/postee/v2/log"
	"github.com/aquasecurity/postee/v2/outputs/customsmtp"
)

const (
	EmailType = "email"
)

var (
	errThereIsNoRecipient = errors.New("there is no recipient")
	lookupMXFunc          = net.LookupMX
)

type EmailOutput struct {
	Name           string
	User           string
	Password       string
	Host           string
	Port           int
	Sender         string
	Recipients     []string
	ClientHostName string
	UseMX          bool
	sendFunc       func(addr string, a customsmtp.Auth, from string, to []string, msg []byte) error
	UseAwsSes      bool
	AwsSesConfig   map[string]string
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

	if email.ClientHostName != "" {
		log.Logger.Infof("Action %q uses a custom client name %q instead of `localhost`", email.Name, email.ClientHostName)
		email.sendFunc = email.sendEmailWithCustomClient
	} else {
		email.sendFunc = customsmtp.SendMail
	}

	log.Logger.Infof("Successfully initialized email output %s", email.Name)
	return nil
}

func (email *EmailOutput) sendEmailWithCustomClient(addr string, a customsmtp.Auth, from string, to []string, msg []byte) error {
	log.Logger.Infof("Sending an email via Custom client for action %q", email.Name)

	c, err := customsmtp.Dial(addr)
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.Hello(email.ClientHostName); err != nil {
		return err
	}

	if ok, _ := c.Extension("STARTTLS"); ok {
		config := &tls.Config{ServerName: email.Host}
		if err = c.StartTLS(config); err != nil {
			return err
		}
	}
	if a != nil {
		if err = c.Auth(a); err != nil {
			return err
		}
	}
	if err = c.Mail(from); err != nil {
		return err
	}
	for _, addr := range to {
		if err = c.Rcpt(addr); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	_, err = w.Write(msg)
	if err != nil {
		return err
	}
	err = w.Close()
	if err != nil {
		return err
	}
	return c.Quit()
}

func (email *EmailOutput) Terminate() error {
	log.Logger.Debug("Email output terminated")
	return nil
}

func (email *EmailOutput) GetLayoutProvider() layout.LayoutProvider {
	return new(formatting.HtmlProvider)
}

func (email *EmailOutput) Send(content map[string]string) (data.OutputResponse, error) {
	log.Logger.Infof("Sending to email via %q", email.Name)
	subject := content["title"]
	body := content["description"]
	port := strconv.Itoa(email.Port)
	recipients := getHandledRecipients(email.Recipients, &content, email.Name)
	if len(recipients) == 0 {
		return data.OutputResponse{}, errThereIsNoRecipient
	}

	if email.UseAwsSes {
		return email.sendViaAwsSesService(email.AwsSesConfig, subject, body, recipients)
	}

	msg := fmt.Sprintf(
		"To: %s\r\n"+
			"From: %s\r\n"+
			"Subject: %s\r\n"+
			"Content-Type: text/html; charset=UTF-8\r\n\r\n%s\r\n",
		strings.Join(recipients, ","), email.Sender, subject, body)

	if email.UseMX {
		email.sendViaMxServers(port, msg, recipients)
		return data.OutputResponse{}, nil
	}

	addr := email.Host + ":" + port
	var auth customsmtp.Auth
	if len(email.Password) > 0 && len(email.User) > 0 {
		auth = customsmtp.PlainAuth("", email.User, email.Password, email.Host)
	}

	err := email.sendFunc(addr, auth, email.Sender, recipients, []byte(msg))
	if err != nil {
		log.Logger.Errorf("failed to send email: %v", err)
		return data.OutputResponse{}, err
	}
	log.Logger.Infof("Email was sent successfully from '%s' through '%s'", email.User, addr)
	return data.OutputResponse{}, nil
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

func (email *EmailOutput) sendViaAwsSesService(awsConfig map[string]string,
	subject, body string, recipients []string) (data.OutputResponse, error) {
	log.Logger.Debugf("Sending to email via %q using SES", email.Name)

	// Create a new AWS session
	sess, err := getAwsSession(awsConfig)
	if err != nil {
		log.Logger.Errorf("Error sending email - %s", err)
		return data.OutputResponse{}, err
	}

	// Create a new SES service client
	svc := ses.New(sess)

	emailInput := &ses.SendEmailInput{
		Destination: &ses.Destination{
			ToAddresses: prepareToEmailAddressList(recipients),
		},
		Message: &ses.Message{
			Body: &ses.Body{
				Html: &ses.Content{
					Data: aws.String(body),
				},
			},
			Subject: &ses.Content{
				Data: aws.String(subject),
			},
		},
		Source: aws.String(awsConfig["fromEmailAddress"]),
	}

	sourceArnConfig := awsConfig["arn"]
	if sourceArnConfig != "" {
		emailInput.SourceArn = aws.String(sourceArnConfig)
	}

	// Send the email
	output, err := svc.SendEmail(emailInput)
	if err != nil {
		log.Logger.Errorf("Error sending email - %s", err)
		return data.OutputResponse{}, err
	} else {
		log.Logger.Debugf("The message was sent successfully via aws-ses aws-messageId:%s", *output.MessageId)
		return data.OutputResponse{Key: *output.MessageId}, err
	}

}

func prepareToEmailAddressList(recipients []string) []*string {
	// Convert to array of string pointers
	toAddresses := make([]*string, len(recipients))
	for i, str := range recipients {
		toAddresses[i] = aws.String(str)
	}

	return toAddresses
}

func getAwsSession(awsConfig map[string]string) (*session.Session, error) {
	// Create a new AWS session
	awsRegion := awsConfig["awsRegion"]
	sess, err := session.NewSession(&aws.Config{
		Credentials: credentials.NewStaticCredentials(awsConfig["id"], awsConfig["secretAccessKey"], awsConfig["awsSessionToken"]),
		Region:      aws.String(awsRegion),
	})

	if err != nil {
		log.Logger.Errorf("Failed sending email - failed to create session with AWS for given credentials %s", err)
		return nil, err
	}
	roleToAssume := awsConfig["assumeRole"]
	if roleToAssume != "" {
		stsSvc := sts.New(sess)

		result, err := stsSvc.AssumeRole(&sts.AssumeRoleInput{
			RoleArn:         aws.String(roleToAssume),
			RoleSessionName: aws.String("SendEmailSession"), // TODO : add some identification if needed for customer_id?.
			DurationSeconds: aws.Int64(900),
		})

		if err != nil {
			log.Logger.Errorf("Failed sending email - Failed assuming role: %s", err)
			return nil, err
		}

		tempCreds := result.Credentials
		tempSession, err := session.NewSession(&aws.Config{
			Credentials: credentials.NewStaticCredentials(*tempCreds.AccessKeyId, *tempCreds.SecretAccessKey, *tempCreds.SessionToken),
			Region:      aws.String(awsRegion),
		})

		if err != nil {
			log.Logger.Errorf("Failed sending email - Failed creating session for assumed role: %s", err)
			return nil, err
		}

		return tempSession, nil
	}

	return sess, nil
}
