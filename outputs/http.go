package outputs

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/layout"
)

type HTTPClient struct {
	Name    string
	Client  http.Client
	URL     *url.URL
	Method  string
	Body    string
	Headers map[string][]string
}

func (hc *HTTPClient) GetName() string {
	return hc.Name
}

func (hc *HTTPClient) Init() error {
	hc.Name = "HTTP Output"
	return nil
}

func (hc HTTPClient) Send(m map[string]string) error {
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
		log.Println("error during HTTP Client execution: ", err.Error())
		return err
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read HTTP response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("http status NOT OK: HTTP %d %s, response: %s", resp.StatusCode, http.StatusText(resp.StatusCode), string(b))
	}

	log.Printf("http execution to url %s successful", hc.URL)
	return nil
}

func (hc HTTPClient) Terminate() error {
	log.Printf("HTTP output terminated\n")
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
		Type:    "http",
	}
}
