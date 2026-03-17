package outputs

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWebhookOutput_Send_WithHeaders(t *testing.T) {
	tests := []struct {
		name            string
		headers         map[string][]string
		expectedHeaders map[string]string
	}{
		{
			name: "Bearer token auth",
			headers: map[string][]string{
				"Authorization": {"Bearer test-token-123"},
			},
			expectedHeaders: map[string]string{
				"Authorization": "Bearer test-token-123",
				"Content-Type":  "application/json",
			},
		},
		{
			name: "Basic auth",
			headers: map[string][]string{
				"Authorization": {"Basic dXNlcjpwYXNz"},
			},
			expectedHeaders: map[string]string{
				"Authorization": "Basic dXNlcjpwYXNz",
				"Content-Type":  "application/json",
			},
		},
		{
			name:    "No headers",
			headers: nil,
			expectedHeaders: map[string]string{
				"Content-Type": "application/json",
			},
		},
		{
			name: "Multiple custom headers",
			headers: map[string][]string{
				"Authorization": {"Bearer token"},
				"X-Custom":      {"custom-value"},
			},
			expectedHeaders: map[string]string{
				"Authorization": "Bearer token",
				"X-Custom":      "custom-value",
				"Content-Type":  "application/json",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedHeaders http.Header

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedHeaders = r.Header
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			webhook := &WebhookOutput{
				Name:    "test-webhook",
				Url:     server.URL,
				Headers: tt.headers,
			}

			_, err := webhook.Send(map[string]string{"description": `{"test": "data"}`})
			assert.NoError(t, err)

			for key, expectedValue := range tt.expectedHeaders {
				assert.Equal(t, expectedValue, capturedHeaders.Get(key), "Header %s mismatch", key)
			}
		})
	}
}

func TestWebhookOutput_Send_ErrorCases(t *testing.T) {
	t.Run("Bad URL", func(t *testing.T) {
		webhook := &WebhookOutput{
			Name: "test-webhook",
			Url:  "not-a-valid-url://invalid",
		}

		_, err := webhook.Send(map[string]string{"description": `{}`})
		assert.Error(t, err)
	})

	t.Run("Server returns error status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("Unauthorized"))
		}))
		defer server.Close()

		webhook := &WebhookOutput{
			Name: "test-webhook",
			Url:  server.URL,
		}

		_, err := webhook.Send(map[string]string{"description": `{}`})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Unauthorized")
	})
}
