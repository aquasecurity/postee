package outputs

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEmailOutput_Send(t *testing.T) {
	t.Run("happy path send mail, server supports no AUTH", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Unable to create listener: %v", err)
		}
		defer l.Close()

		errCh := make(chan error)
		go func() {
			testSMTPServerFunc(errCh, l)
		}()

		host, port, err := net.SplitHostPort(l.Addr().String())
		portNum, err := strconv.Atoi(port)
		require.NoError(t, err)

		ec := EmailOutput{
			Name:       "my-email",
			Host:       host,
			Port:       portNum,
			Sender:     "sender@mailer.com",
			Recipients: []string{"anything@fubar.com"},
		}
		err = ec.Send(map[string]string{"foo": "bar"})
		require.Equal(t, "smtp: server doesn't support AUTH", err.Error())

		err = <-errCh
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	})

	t.Run("happy path send email via mx server", func(t *testing.T) {
		server := strings.Join(strings.Split(sendMailServer, "\n"), "\r\n")
		var cmdbuf bytes.Buffer
		bcmdbuf := bufio.NewWriter(&cmdbuf)
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Unable to create listener: %v", err)
		}
		defer l.Close()

		var done = make(chan struct{})
		go func(data []string) {
			testMXServerFunc(data, done, l, t, bcmdbuf)
		}(strings.Split(server, "\r\n"))

		host, port, err := net.SplitHostPort(l.Addr().String())
		require.NoError(t, err)
		portNum, err := strconv.Atoi(port)
		require.NoError(t, err)

		oldLookupFunc := lookupMXFunc
		lookupMXFunc = func(name string) ([]*net.MX, error) {
			return []*net.MX{
				{
					Host: host,
				},
			}, nil
		}
		defer func() {
			lookupMXFunc = oldLookupFunc
		}()

		ec := EmailOutput{
			Name:       "my-email",
			Host:       host,
			Port:       portNum,
			Sender:     "sender@mailer.com",
			Recipients: []string{fmt.Sprintf("foo@%s", "anythingfubar.com")},
			UseMX:      true,
		}
		err = ec.Send(map[string]string{"foo": "bar"})
		require.NoError(t, err)
	})
}

// The following code snippets are adapted for testing from golang/smtp
// package. Reference of the test code can be found
// https://github.com/golang/go/blob/3042ba34db86853c7035046716c4a00b2dbef2ed/src/net/smtp/smtp_test.go#L749

var sendMailServer = `220 hello world
502 EH?
250 mx.google.com at your service
250 Sender ok
250 Receiver ok
354 Go ahead
250 Data ok
221 Goodbye
`

func testMXServerFunc(data []string, done chan struct{}, l net.Listener, t *testing.T, bcmdbuf *bufio.Writer) {
	defer close(done)
	conn, err := l.Accept()
	if err != nil {
		t.Errorf("Accept error: %v", err)
		return
	}
	defer conn.Close()

	tc := textproto.NewConn(conn)
	for i := 0; i < len(data) && data[i] != ""; i++ {
		tc.PrintfLine(data[i])
		for len(data[i]) >= 4 && data[i][3] == '-' {
			i++
			tc.PrintfLine(data[i])
		}
		if data[i] == "221 Goodbye" {
			return
		}
		read := false
		for !read || data[i] == "354 Go ahead" {
			msg, err := tc.ReadLine()
			bcmdbuf.Write([]byte(msg + "\r\n"))
			read = true
			if err != nil {
				t.Errorf("Read error: %v", err)
				return
			}
			if data[i] == "354 Go ahead" && msg == "." {
				break
			}
		}
	}
}

func testSMTPServerFunc(errCh chan error, l net.Listener) {
	defer close(errCh)
	conn, err := l.Accept()
	if err != nil {
		errCh <- fmt.Errorf("Accept: %v", err)
		return
	}
	defer conn.Close()

	tc := textproto.NewConn(conn)
	tc.PrintfLine("220 hello world")
	msg, err := tc.ReadLine()
	if err != nil {
		errCh <- fmt.Errorf("ReadLine error: %v", err)
		return
	}
	const wantMsg = "EHLO localhost"
	if msg != wantMsg {
		errCh <- fmt.Errorf("unexpected response %q; want %q", msg, wantMsg)
		return
	}
	err = tc.PrintfLine("250 mx.google.com at your service")
	if err != nil {
		errCh <- fmt.Errorf("PrintfLine: %v", err)
		return
	}
}
