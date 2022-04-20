package actions

import (
	"fmt"
	"net"
	"net/smtp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func mockSend(errToReturn error, emailSent *int) (func(string, smtp.Auth, string, []string, []byte) error, *emailRecorder) {
	r := new(emailRecorder)
	return func(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
		*r = emailRecorder{addr, a, from, to, msg}
		if errToReturn == nil {
			*emailSent++
		}
		return errToReturn
	}, r
}

type emailRecorder struct {
	addr string
	auth smtp.Auth
	from string
	to   []string
	msg  []byte
}

func TestEmailAction_Send(t *testing.T) {
	testCases := []struct {
		name               string
		lookupMXFunc       func(name string) ([]*net.MX, error)
		emailAction        *EmailAction
		expectedMessage    string
		sendError          error
		expectedError      error
		expectedSentEmails int
	}{
		{
			name: "happy path, with auth, server supports auth",
			expectedMessage: fmt.Sprintf("To: anything@fubar.com\r\n" +
				"From: sender@mailer.com\r\n" +
				"Subject: email subject\r\n" +
				"Content-Type: text/html; charset=UTF-8\r\n" +
				"\r\n" +
				"foo bar baz body\r\n"),
			expectedSentEmails: 1,
		},
		{
			name: "happy path, use multiple mx servers, no auth",
			lookupMXFunc: func(name string) ([]*net.MX, error) {
				return []*net.MX{
					{
						Host: "127.0.0.1",
					},
					{
						Host: "128.0.0.1",
					},
				}, nil
			},
			expectedMessage: fmt.Sprintf("To: anything@fubar.com\r\n" +
				"From: sender@mailer.com\r\n" +
				"Subject: email subject\r\n" +
				"Content-Type: text/html; charset=UTF-8\r\n" +
				"\r\n" +
				"foo bar baz body\r\n"),
			expectedSentEmails: 1,
		},
		{
			name:          "sad path, no recipients",
			emailAction:   &EmailAction{Recipients: []string{}},
			expectedError: errThereIsNoRecipient,
		},
		{
			name:               "sad path, client uses AUTH, smtp server does not support AUTH",
			sendError:          fmt.Errorf("smtp: server doesn't support AUTH"),
			expectedError:      fmt.Errorf("smtp: server doesn't support AUTH"),
			expectedMessage:    "",
			expectedSentEmails: 0,
		},
		{
			name: "sad path, use mx server, invalid recipient,",
			emailAction: &EmailAction{
				Name:       "my-email",
				User:       "user",
				Password:   "pass",
				Host:       "127.0.0.1",
				Port:       587,
				Sender:     "sender@mailer.com",
				Recipients: []string{"invalid recipient"},
				UseMX:      true,
			},
			expectedSentEmails: 0,
		},
		{
			name: "sad path, no mx server available",
			lookupMXFunc: func(name string) ([]*net.MX, error) {
				return []*net.MX{}, fmt.Errorf("no such host")
			},
			expectedSentEmails: 0,
		},
		{
			name: "sad path, use mx servers, error sending email",
			lookupMXFunc: func(name string) ([]*net.MX, error) {
				return []*net.MX{
					{
						Host: "127.0.0.1",
					},
				}, nil
			},
			expectedMessage: fmt.Sprintf("To: anything@fubar.com\r\n" +
				"From: sender@mailer.com\r\n" +
				"Subject: email subject\r\n" +
				"Content-Type: text/html; charset=UTF-8\r\n" +
				"\r\n" +
				"foo bar baz body\r\n"),
			sendError:          fmt.Errorf("internal server error"),
			expectedSentEmails: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var eo EmailAction
			if tc.emailAction != nil {
				eo = *tc.emailAction
			} else {
				eo = EmailAction{
					Name:       "my-email",
					User:       "user",
					Password:   "pass",
					Host:       "127.0.0.1",
					Port:       587,
					Sender:     "sender@mailer.com",
					Recipients: []string{"anything@fubar.com"},
				}
			}

			var emailsSent int
			f, r := mockSend(tc.sendError, &emailsSent)
			eo.sendFunc = f

			if tc.lookupMXFunc != nil {
				oldLookupMXFunc := lookupMXFunc
				lookupMXFunc = tc.lookupMXFunc
				defer func() {
					lookupMXFunc = oldLookupMXFunc
				}()
				eo.UseMX = true
			}

			err := eo.Send(map[string]string{"description": "foo bar baz body", "title": "email subject"})
			switch {
			case tc.expectedError != nil:
				assert.Equal(t, tc.expectedError, err, tc.name)
				assert.Equal(t, tc.expectedSentEmails, emailsSent, tc.name)
			default:
				assert.NoError(t, err, tc.name)
				assert.Equal(t, tc.expectedSentEmails, emailsSent, tc.name)
				assert.Equal(t, tc.expectedMessage, string(r.msg), tc.name)
			}
		})
	}
}
