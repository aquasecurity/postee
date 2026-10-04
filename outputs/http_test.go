package outputs

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/aquasecurity/postee/v2/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var httpTestEvent = map[string]string{"description": "foo bar baz header"}

// newHTTPTestServer starts a test server that is closed when the test ends.
func newHTTPTestServer(t *testing.T, handler http.HandlerFunc) *url.URL {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	u, err := url.Parse(ts.URL)
	require.NoError(t, err)
	return u
}

func TestHTTPClient_Init(t *testing.T) {
	ec := HTTPClient{}
	require.NoError(t, ec.Init())
}

func TestHTTPClient_GetName(t *testing.T) {
	ec := HTTPClient{}
	require.NoError(t, ec.Init())
	require.Equal(t, "HTTP Output", ec.GetName())
}

func TestHTTPClient_GetType(t *testing.T) {
	ec := HTTPClient{}
	assert.Equal(t, "http", ec.GetType())
}

func TestHTTPClient_Terminate(t *testing.T) {
	assert.NoError(t, HTTPClient{}.Terminate())
}

func TestHTTPClient_GetLayoutProvider(t *testing.T) {
	assert.Nil(t, HTTPClient{}.GetLayoutProvider())
}

func TestHTTPClient_CloneSettings(t *testing.T) {
	u, err := url.Parse("https://example.com/hook")
	require.NoError(t, err)
	ec := HTTPClient{Name: "my http", URL: u, Method: http.MethodPost, Headers: map[string][]string{"fookey": {"bar value"}}}

	assert.Equal(t, &data.OutputSettings{
		Name:    "my http",
		Url:     "https://example.com/hook",
		Method:  http.MethodPost,
		Headers: map[string][]string{"fookey": {"bar value"}},
		Enable:  true,
		Type:    "http",
	}, ec.CloneSettings())
}

func TestHTTPClient_SendRequest(t *testing.T) {
	type receivedRequest struct {
		method string
		header http.Header
		body   string
	}
	testCases := []struct {
		name   string
		method string
		body   string
	}{
		{name: "get", method: http.MethodGet},
		{name: "post with a body", method: http.MethodPost, body: "foo body"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			received := make(chan receivedRequest, 1)
			u := newHTTPTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				received <- receivedRequest{method: r.Method, header: r.Header.Clone(), body: string(b)}
			})
			ec := HTTPClient{URL: u, Method: tc.method, Body: tc.body, Headers: map[string][]string{"fookey": {"bar value"}}}

			_, err := ec.Send(httpTestEvent)
			require.NoError(t, err)

			var got receivedRequest
			select {
			case got = <-received:
			case <-time.After(5 * time.Second):
				t.Fatal("the server did not receive a request")
			}
			assert.Equal(t, tc.method, got.method)
			assert.Equal(t, tc.body, got.body)
			assert.Equal(t, "bar value", got.header.Get("fookey"))
			assert.Equal(t, "foo bar baz header", got.header.Get("POSTEE_EVENT"))
			// Send adds the event header to a copy, not to the headers of the output
			assert.Equal(t, map[string][]string{"fookey": {"bar value"}}, ec.Headers)
		})
	}
}

func TestHTTPClient_SendStatus(t *testing.T) {
	testCases := []struct {
		status        int
		expectedError string // empty: Send succeeds
	}{
		{status: http.StatusOK},
		{status: http.StatusNoContent},
		{status: 299},
		{status: http.StatusMultipleChoices, expectedError: "http status NOT OK: HTTP 300 Multiple Choices, response: server response"},
		{status: http.StatusNotFound, expectedError: "http status NOT OK: HTTP 404 Not Found, response: server response"},
		{status: http.StatusInternalServerError, expectedError: "http status NOT OK: HTTP 500 Internal Server Error, response: server response"},
	}

	for _, tc := range testCases {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			u := newHTTPTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte("server response"))
			})

			_, err := HTTPClient{URL: u, Method: http.MethodGet}.Send(httpTestEvent)
			if tc.expectedError == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tc.expectedError)
		})
	}
}

// The text of a connection error comes from the system (for example the DNS resolver), so these tests check the
// error type, not the text.
func TestHTTPClient_SendErrors(t *testing.T) {
	t.Run("unknown host", func(t *testing.T) {
		// the dialer fails like the DNS lookup of an unknown host, so the test does not need a network
		lookupErr := &net.DNSError{Err: "no such host", Name: "path-to-nowhere.invalid", IsNotFound: true}
		ec := HTTPClient{
			URL:    &url.URL{Scheme: "http", Host: "path-to-nowhere.invalid"},
			Method: http.MethodGet,
			Client: http.Client{Transport: &http.Transport{
				DialContext: func(context.Context, string, string) (net.Conn, error) {
					return nil, &net.OpError{Op: "dial", Net: "tcp", Err: lookupErr}
				},
			}},
		}

		_, err := ec.Send(httpTestEvent)
		var dnsErr *net.DNSError
		require.ErrorAs(t, err, &dnsErr)
		assert.Equal(t, "path-to-nowhere.invalid", dnsErr.Name)
	})

	t.Run("server not reachable", func(t *testing.T) {
		ts := httptest.NewServer(http.NotFoundHandler())
		u, err := url.Parse(ts.URL)
		require.NoError(t, err)
		ts.Close()

		_, err = HTTPClient{URL: u, Method: http.MethodGet}.Send(httpTestEvent)
		var opErr *net.OpError
		require.ErrorAs(t, err, &opErr)
		assert.Equal(t, "dial", opErr.Op)
	})

	t.Run("response body shorter than its length", func(t *testing.T) {
		u := newHTTPTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "10")
			_, _ = w.Write([]byte("abc"))
		})

		_, err := HTTPClient{URL: u, Method: http.MethodGet}.Send(httpTestEvent)
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		assert.ErrorContains(t, err, "unable to read HTTP response")
	})
}

// closeRecorder is a response body that records whether it was closed.
type closeRecorder struct {
	io.Reader
	closed bool
}

func (c *closeRecorder) Close() error {
	c.closed = true
	return nil
}

// roundTripFunc returns a response without a network.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestHTTPClient_SendClosesResponseBody(t *testing.T) {
	testCases := []struct {
		name   string
		status int
		body   io.Reader
	}{
		{name: "success", status: http.StatusOK, body: strings.NewReader("ok")},
		{name: "error status", status: http.StatusInternalServerError, body: strings.NewReader("internal server error")},
		{name: "unreadable body", status: http.StatusOK, body: iotest.ErrReader(errors.New("read failed"))},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body := &closeRecorder{Reader: tc.body}
			ec := HTTPClient{
				URL:    &url.URL{Scheme: "http", Host: "postee.test"},
				Method: http.MethodGet,
				Client: http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: tc.status, Body: body, Request: r}, nil
				})},
			}

			_, _ = ec.Send(httpTestEvent)
			assert.True(t, body.closed, "Send must close the response body")
		})
	}
}
