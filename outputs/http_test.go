package outputs

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPClient_Init(t *testing.T) {
	ec := HTTPClient{}
	require.NoError(t, ec.Init())
}

func TestHTTPClient_GetName(t *testing.T) {
	ec := HTTPClient{}
	require.NoError(t, ec.Init())
	require.Equal(t, "HTTP Output", ec.GetName())
}

func TestHTTPClient_Send(t *testing.T) {
	testCases := []struct {
		name           string
		method         string
		body           string
		testServerFunc http.HandlerFunc
		expectedError  string
	}{
		{
			name:   "happy path method get",
			method: http.MethodGet,
			testServerFunc: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "bar value", r.Header.Get("fookey"))
				assert.Equal(t, "foo bar baz header", r.Header.Get("POSTEE_EVENT"))
				fmt.Fprintln(w, "Hello, client")
			},
		},
		{
			name:   "happy path method post",
			method: http.MethodPost,
			body:   "foo body",
			testServerFunc: func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "bar value", r.Header.Get("fookey"))
				assert.Equal(t, "foo bar baz header", r.Header.Get("POSTEE_EVENT"))

				b, _ := ioutil.ReadAll(r.Body)
				assert.Equal(t, "foo body", string(b))

				fmt.Fprintln(w, "Hello, client")
			},
		},
		{
			name:   "sad path method get - server unavailable",
			method: http.MethodGet,
			testServerFunc: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("internal server error"))
			},
			expectedError: "http status NOT OK: HTTP 500 Internal Server Error, response: internal server error",
		},
		{
			name:          "sad path method get - bad url",
			method:        http.MethodGet,
			expectedError: `Get "http://path-to-nowhere": dial tcp: lookup path-to-nowhere: no such host`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var testUrl *url.URL
			if tc.testServerFunc != nil {
				ts := httptest.NewServer(tc.testServerFunc)
				testUrl, _ = url.Parse(ts.URL)
			} else {
				testUrl, _ = url.Parse("http://path-to-nowhere")
			}

			ec := HTTPClient{
				URL:     testUrl,
				Body:    tc.body,
				Method:  tc.method,
				Headers: map[string][]string{"fookey": {"bar value"}},
			}
			switch {
			case tc.expectedError != "":
				require.EqualError(t, ec.Send(map[string]string{"description": "foo bar baz header"}), tc.expectedError, tc.name)
			default:
				require.NoError(t, ec.Send(map[string]string{"description": "foo bar baz header"}), tc.name)
			}
		})
	}
}
