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
				Timeout: 120,
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
				Timeout: 0,
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
				Timeout: 1,
			},
			content: map[string]string{
				"description": "test description",
			},
			wantError: "bad URL",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			savedNewClient := newClient
			newClient = func(timeout int) http.Client {
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
				return *client
			}
			defer func() {
				newClient = savedNewClient
			}()

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
		timeout     int
		wantTimeout time.Duration
	}{
		{
			name:        "timeout 0",
			timeout:     0,
			wantTimeout: 120000000000,
		},
		{
			name:        "timeout 60",
			timeout:     60,
			wantTimeout: 60000000000,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newClient(test.timeout)

			require.Equal(t, test.wantTimeout, client.Timeout)
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
