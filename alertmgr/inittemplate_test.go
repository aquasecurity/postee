package alertmgr

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
)

var (
	regoRule = "package postee.slack"
)

func TestInitTemplate(t *testing.T) {
	savedGetHttpClient := getHttpClient
	getHttpClient = getMockedHttpClient
	defaultRegoFolder := "rego-templates"
	commonRegoFolder := defaultRegoFolder + "/common"
	testRego := defaultRegoFolder + "/rego1.rego"
	err := os.Mkdir(defaultRegoFolder, 0777)
	if err != nil {
		t.Fatalf("Can't create rego folder: %v", err)
	}
	err = os.Mkdir(commonRegoFolder, 0777)
	if err != nil {
		t.Fatalf("Can't create rego folder: %v", err)
	}

	err = ioutil.WriteFile(testRego, []byte(regoRule), 0644)

	if err != nil {
		t.Fatalf("Can't write rego: %v", err)
	}

	defer func() {
		os.Remove(testRego)
		os.Remove(commonRegoFolder)
		os.Remove(defaultRegoFolder)
		getHttpClient = savedGetHttpClient
	}()

	tests := []struct {
		template    *Template
		caseDesc    string
		expectedCls string
	}{
		{
			template: &Template{
				Name:               "legacy-html",
				LegacyScanRenderer: "html",
			},
			caseDesc:    "Legacy mode test",
			expectedCls: "*formatting.legacyScnEvaluator",
		},
		{
			template: &Template{
				Name:        "build-in",
				RegoPackage: "postee.slack",
			},
			caseDesc:    "Build-in rego package",
			expectedCls: "*regoservice.regoEvaluator",
		},
		{
			template: &Template{
				Name: "from-url",
				Url:  "http://localhost/slack.rego",
			},
			caseDesc:    "Loading rego from url",
			expectedCls: "*regoservice.regoEvaluator",
		},
		{
			template: &Template{
				Name: "inline",
				Body: "package postee.inline",
			},
			caseDesc:    "Loading rego from yaml config",
			expectedCls: "*regoservice.regoEvaluator",
		},
	}
	for _, test := range tests {
		doInitTemplate(t, test.caseDesc, test.template, test.expectedCls)
	}

}
func doInitTemplate(t *testing.T, caseDesc string, template *Template, expectedCls string) {
	demoCtx := Instance()
	err := demoCtx.initTemplate(template)
	if err != nil {
		t.Fatalf("[%s] Unexpected error: %v", caseDesc, err)
	}
	initialized, ok := demoCtx.templates[template.Name]
	if !ok {
		t.Fatalf("[%s] template %s is not initialized", caseDesc, template.Name)
	}
	actualCls := fmt.Sprintf("%T", initialized)
	if actualCls != expectedCls {
		t.Errorf("[%s] Unexpected type of input evaluator. Expected %s, got %s \n", caseDesc, expectedCls, actualCls)
	}
	//TODO call initialized.Eval() to distinguish evaluators received
}

//stuff for mocking http requests goes below

func getMockedHttpClient() *http.Client {
	return NewTestClient(responseWithRego)
}

// RoundTripFunc
type RoundTripFunc func(req *http.Request) *http.Response

// RoundTrip
func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { //this is kind of wrapper where original function is used in interface implementation
	return f(req), nil
}

//NewTestClient returns *http.Client with Transport replaced to avoid making real calls
func NewTestClient(fn RoundTripFunc) *http.Client {
	return &http.Client{
		Transport: RoundTripFunc(fn),
	}
}
func responseWithRego(req *http.Request) *http.Response {
	return newTestResponse(200, "package custom1")
}

func newTestResponse(status int, response string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       ioutil.NopCloser(bytes.NewBufferString(response)),
		// Must be set to non-nil value or it panics
		Header: make(http.Header),
	}
}
