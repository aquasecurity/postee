package actions

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PagerDuty/go-pagerduty"
	"github.com/stretchr/testify/assert"
)

type fakeClock struct{}

func (fc *fakeClock) Now() time.Time {
	t, _ := time.Parse(time.RFC3339, "2022-09-22T22:07:55-07:00")
	return t
}

func TestPagerdutyClient_Init(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		require.NoError(t, (&PagerdutyClient{
			Name:       "my-pagerduty",
			AuthToken:  "123456",
			RoutingKey: "foobarbaz",
		}).Init())
	})

	t.Run("sad path, no auth token", func(t *testing.T) {
		assert.Equal(t, "pagerduty auth token is required to send events", (&PagerdutyClient{
			Name:       "my-pagerduty",
			RoutingKey: "foobarbaz",
		}).Init().Error())
	})

	t.Run("sad path, no routing key", func(t *testing.T) {
		assert.Equal(t, "pagerduty routing key is required to send events", (&PagerdutyClient{
			Name:      "my-pagerduty",
			AuthToken: "123456",
		}).Init().Error())
	})
}

func TestPagerdutyClient_Send(t *testing.T) {
	testCases := []struct {
		name            string
		handlerFunc     http.HandlerFunc
		expectedError   string
		pagerdutyClient PagerdutyClient
		inputEvent      map[string]string
	}{
		{
			name: "happy path",
			handlerFunc: func(writer http.ResponseWriter, request *http.Request) {
				b, _ := io.ReadAll(request.Body)
				assert.JSONEq(t, `{"routing_key":"123456","event_action":"trigger","payload":{"summary":"my fancy title","source":"postee","severity":"critical","timestamp":"2022-09-22T22:07:55-07:00","custom_details":"foo bar baz details"}}`, string(b))
				_, _ = fmt.Fprint(writer, `{"status": "ok", "dedup_key": "yes", "message": "ok"}`)
			},
			pagerdutyClient: PagerdutyClient{
				Name:       "my-pagerduty",
				AuthToken:  "foo-bar-baz",
				RoutingKey: "123456",
			},
			inputEvent: map[string]string{
				"description": "foo bar baz details",
				"title":       "my fancy title",
			},
		},
		{
			name: "sad path, pagerduty api returns an error",
			handlerFunc: func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(http.StatusInternalServerError)
			},
			pagerdutyClient: PagerdutyClient{
				Name:       "my-pagerduty",
				AuthToken:  "foo-bar-baz",
				RoutingKey: "123456",
			},
			inputEvent: map[string]string{
				"description": "foo bar baz details",
				"title":       "my fancy title",
			},
			expectedError: "failed to send event to pagerduty: HTTP response with status code 500 does not contain Content-Type: application/json",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(tc.handlerFunc)
			defer ts.Close()

			tc.pagerdutyClient.client = pagerduty.NewClient(tc.pagerdutyClient.AuthToken, pagerduty.WithV2EventsAPIEndpoint(ts.URL))
			tc.pagerdutyClient.clock = &fakeClock{}

			err := tc.pagerdutyClient.Send(tc.inputEvent)
			switch {
			case tc.expectedError != "":
				assert.Equal(t, tc.expectedError, err.Error(), tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}
		})
	}
}
