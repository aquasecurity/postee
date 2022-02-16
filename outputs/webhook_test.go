package outputs

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestWebhook_GetName(t *testing.T) {
	webhook := WebhookOutput{Name: "webhook output"}
	require.NoError(t, webhook.Init())
	require.Equal(t, "webhook output", webhook.GetName())
}

func TestWebhook_Send(t *testing.T) {
	tests := []struct {
		name      string
		webhook   WebhookOutput
		content   map[string]string
		wantError string
	}{
		{
			name: "happy path",
			webhook: WebhookOutput{
				Name:    "testName",
				Url:     "https://testUrl/webhook",
				Timeout: "120s",
			},
			content: map[string]string{
				"description": "test description",
			},
		},
		{
			name: "sad path (timeout error)",
			webhook: WebhookOutput{
				Name:    "testName",
				Url:     "https://testUrl/webhook",
				Timeout: "0s",
			},
			content: map[string]string{
				"description": "test description",
			},
			wantError: "Timeout error",
		},
		{
			name: "sad path (Bad URL error)",
			webhook: WebhookOutput{
				Name:    "testName",
				Url:     "badUrl",
				Timeout: "1m",
			},
			content: map[string]string{
				"description": "test description",
			},
			wantError: "bad URL",
		},
	}

	savedNewClient := newClient
	defer func() { newClient = savedNewClient }()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			newClient = func(timeout string) (http.Client, error) {
				client := NewTestClient(func(req *http.Request) *http.Response {
					resp := &http.Response{Header: make(http.Header)}
					switch test.wantError {
					case "Timeout error":
						resp.StatusCode = http.StatusRequestTimeout
						resp.Body = ioutil.NopCloser(bytes.NewBufferString(`Timeout error`))
						resp.Status = "error"
					default:
						resp.StatusCode = http.StatusOK
						resp.Body = ioutil.NopCloser(bytes.NewBufferString(`OK`))
					}
					return resp
				})
				return *client, nil
			}

			err := test.webhook.Send(test.content)
			if test.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.wantError)
			} else {
				require.NoError(t, err)
			}
		})

	}
}

func TestNewClient(t *testing.T) {
	tests := []struct {
		name        string
		timeout     string
		wantTimeout time.Duration
		wantError   string
	}{
		{
			name:        "timeout 0",
			timeout:     "0",
			wantTimeout: 120000000000,
		},
		{
			name:        "timeout 60",
			timeout:     "60s",
			wantTimeout: 60000000000,
		},
		{
			name:      "bad timeout",
			timeout:   "60sm",
			wantError: "invalid duration specified",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, err := newClient(test.timeout)

			if test.wantError != "" {
				assert.NotNil(t, err)
				require.Contains(t, err.Error(), test.wantError)
			} else {
				require.Equal(t, test.wantTimeout, client.Timeout)
			}
		})
	}
}

// RoundTripFunc .
type RoundTripFunc func(req *http.Request) *http.Response

// RoundTrip .
func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	if !strings.HasPrefix(req.URL.Scheme, "http") {
		return nil, fmt.Errorf("bad URL")
	}
	return f(req), nil
}

//NewTestClient returns *http.Client with Transport replaced to avoid making real calls
func NewTestClient(fn RoundTripFunc) *http.Client {
	return &http.Client{
		Transport: RoundTripFunc(fn),
	}
}
