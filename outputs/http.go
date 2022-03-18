package outputs

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/aquasecurity/postee/v2/layout"
)

type HTTPClient struct {
	Name        string
	Client      http.Client
	URL         *url.URL
	Method      string
	BodyFile    string
	BodyContent string
	Headers     map[string][]string
}

func (hc *HTTPClient) GetName() string {
	return hc.Name
}

func (hc *HTTPClient) Init() error {
	return nil
}

func (hc HTTPClient) Send(m map[string]string) error {
	// encode headers as base64 to conform HTTP spec
	// https://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.2
	pe := base64.StdEncoding.EncodeToString([]byte(m["description"]))

	req, err := http.NewRequest(hc.Method, hc.URL.String(), nil)
	if err != nil {
		return fmt.Errorf("unable to initialize http request err: %w", err)
	}

	req.Header.Add("Postee-Event", pe) // preserve and transmit postee header
	for k, vals := range hc.Headers {
		for _, val := range vals {
			req.Header.Add(k, val)
		}
	}

	if len(hc.BodyFile) > 0 {
		bf, err := os.Open(hc.BodyFile)
		if err != nil {
			return fmt.Errorf("unable to read body file: %s, err: %w", hc.BodyFile, err)
		}
		req.Body = bf
	}

	if len(hc.BodyContent) > 0 {
		req.Body = io.NopCloser(strings.NewReader(hc.BodyContent))
	}

	resp, err := hc.Client.Do(req)
	if err != nil {
		log.Println("error during HTTP Client execution: ", err.Error())
		return err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read HTTP response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("http status NOT OK: HTTP %d %s, response: %s", resp.StatusCode, http.StatusText(resp.StatusCode), string(b))
	}

	log.Printf("http %s execution to url %s successful", hc.Method, hc.URL)
	return nil
}

func (hc HTTPClient) Terminate() error {
	log.Printf("HTTP output terminated\n")
	return nil
}

func (hc HTTPClient) GetLayoutProvider() layout.LayoutProvider {
	return nil
}
