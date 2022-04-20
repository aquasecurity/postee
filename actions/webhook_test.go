package actions

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebhook_GetName(t *testing.T) {
	webhook := WebhookAction{Name: "webhook action"}
	require.NoError(t, webhook.Init())
	require.Equal(t, "webhook action", webhook.GetName())
}

func TestWebhook_Send(t *testing.T) {
	type response = struct {
		status int
		text   string
	}
	tests := []struct {
		name    string
		webhook WebhookAction
		content map[string]string
		resp    response
		wantErr string
	}{
		{
			name: "happy path",
			webhook: WebhookAction{
				Name:    "testName",
				Url:     "%s/testUrl/webhook",
				Timeout: "120s",
			},
			content: map[string]string{
				"description": "test description",
			},
			resp: response{
				status: http.StatusOK,
				text:   "OK",
			},
		},
		{
			name: "sad path (timeout error)",
			webhook: WebhookAction{
				Name:    "testName",
				Url:     `%s/testUrl/webhook`,
				Timeout: "0s",
			},
			content: map[string]string{
				"description": "test description",
			},
			resp: response{
				status: http.StatusRequestTimeout,
				text:   "Timeout error",
			},
			wantErr: "Sending webhook wrong status: '408'. Body: Timeout error",
		},
		{
			name: "sad path (Bad URL error)",
			webhook: WebhookAction{
				Name:    "testName",
				Url:     "badurl%s",
				Timeout: "1m",
			},
			content: map[string]string{
				"description": "test description",
			},
			wantErr: "unsupported protocol scheme",
		},
	}

	savedNewClient := newClient
	defer func() { newClient = savedNewClient }()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.resp.status)
				_, _ = w.Write([]byte(test.resp.text))
			}))
			defer server.Close()

			test.webhook.Url = fmt.Sprintf(test.webhook.Url, server.URL)

			newClient = func(timeout string) (http.Client, error) {
				client := server.Client()
				return *client, nil
			}

			err := test.webhook.Send(test.content)

			if test.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.wantErr)
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
