package outputs

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/aquasecurity/postee/layout"
)

type HTTPClient struct {
	Name    string
	URL     *url.URL
	Method  string
	Body    string
	Timeout time.Duration
}

func (hc *HTTPClient) GetName() string {
	return hc.Name
}

func (hc *HTTPClient) Init() error {
	hc.Name = "HTTP Client"
	return nil
}

func (hc HTTPClient) Send(m map[string]string) error {
	c := http.Client{
		Timeout: hc.Timeout,
	}

	resp, err := c.Do(&http.Request{
		Method: hc.Method,
		URL:    hc.URL,
		Header: nil, // TODO: Support adding headers
		Body:   io.NopCloser(bytes.NewBufferString(hc.Body)),
	})
	if err != nil {
		log.Println("error during HTTP Client execution: ", err.Error())
		return err
	}

	b, _ := io.ReadAll(resp.Body)
	log.Println(">>>>>>>>>> body: ", string(b))
	return nil
}

func (hc HTTPClient) Terminate() error {
	log.Printf("HTTP output terminated\n")
	return nil
}

func (hc HTTPClient) GetLayoutProvider() layout.LayoutProvider {
	return nil
}
