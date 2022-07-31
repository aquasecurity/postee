package outputs

import (
	"fmt"
	"io"

	"net/http"
	"net/url"
	"strings"

	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/layout"
	"github.com/aquasecurity/postee/v2/log"
)

const (
	HTTPType = "http"
)

type HTTPClient struct {
	Name    string
	Client  http.Client
	URL     *url.URL
	Method  string
	Body    string
	Headers map[string][]string
}

func (hc *HTTPClient) GetType() string {
	return HTTPType
}

func (hc *HTTPClient) GetName() string {
	return hc.Name
}

func (hc *HTTPClient) Init() error {
	hc.Name = "HTTP Output"
	log.Logger.Infof("Successfully initialized HTTP output: %q", hc.Name)
	return nil
}

func (hc HTTPClient) Send(m map[string]string) (string, error) {
	log.Logger.Infof("Sending HTTP via %q", hc.Name)
	headers := make(map[string][]string)
	for k, v := range hc.Headers {
		headers[k] = v
	}

	headers["POSTEE_EVENT"] = []string{m["description"]} // preserve and transmit postee header

	resp, err := hc.Client.Do(&http.Request{
		Method: hc.Method,
		URL:    hc.URL,
		Header: headers,
		Body:   io.NopCloser(strings.NewReader(hc.Body)),
	})
	if err != nil {
		log.Logger.Error(fmt.Errorf("error during HTTP Client execution: %w", err))
		return EmptyID, err
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return EmptyID, fmt.Errorf("unable to read HTTP response: %w", err)
	}

	code := resp.StatusCode
	if code < 200 || code > 299 {
		return EmptyID, fmt.Errorf("http status NOT OK: HTTP %d %s, response: %s", resp.StatusCode, http.StatusText(code), string(b))
	}

	log.Logger.Debugf("http execution to url %s successful", hc.URL)
	return EmptyID, nil
}

func (hc HTTPClient) Terminate() error {
	log.Logger.Debug("HTTP output terminated")
	return nil
}

func (hc HTTPClient) GetLayoutProvider() layout.LayoutProvider {
	return nil
}

func (hc HTTPClient) CloneSettings() *data.OutputSettings {
	return &data.OutputSettings{
		Name:    hc.Name,
		Url:     hc.URL.String(),
		Method:  hc.Method,
		Headers: hc.Headers,
		Enable:  true,
		Type:    HTTPType,
	}
}
