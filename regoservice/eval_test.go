package regoservice

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

var (
	regoHtml = `
	package rego1
	title:="Audit event received"
	result:=sprintf("Audit event received from %s", [input.user])	
`
	input = `{
		"user": "demo"
	}
`
)

func TestBundled(t *testing.T) {
	tests := []struct {
		regoRule       *string
		caseDesc       string
		input          *string
		regoPackage    string
		expectedValues map[string]string
	}{
		{
			regoRule:    &regoHtml,
			caseDesc:    "simple case",
			input:       &input,
			regoPackage: "rego1",
			expectedValues: map[string]string{
				"title":       "Audit event received",
				"description": "Audit event received from demo",
			},
		},
	}
	for _, test := range tests {
		validateBuildInEval(t, test.caseDesc, test.regoRule, test.input, test.regoPackage, test.expectedValues)
	}
}

func validateBuildInEval(t *testing.T, caseDesc string, regoRule *string, input *string, regoPackage string, expectedValues map[string]string) {
	buildinRegoTemplatesSaved := buildinRegoTemplates
	testRego := "rego1.rego"
	buildinRegoTemplates = []string{testRego}

	ioutil.WriteFile(testRego, []byte(*regoRule), 0644)

	defer func() {
		buildinRegoTemplates = buildinRegoTemplatesSaved
		os.Remove(testRego)
	}()
	demo, err := BuildBundledRegoEvaluator(regoPackage)
	if err != nil {
		t.Errorf("received an unexpected error: %v\n", err)
	}
	if demo.IsAggregationSupported() {
		t.Errorf("Shouldn't support aggregation")
	}
	r, err := demo.Eval(parseJson(input), "")
	if err != nil {
		t.Errorf("received an unexpected error: %v\n", err)
	}

	for key, expected := range expectedValues {
		if r[key] != expected {
			t.Errorf("Incorrect %s: expected %s, got %s\n", key, expected, r[key])
		}

	}
}
func parseJson(in *string) map[string]interface{} {
	r := make(map[string]interface{})
	if err := json.Unmarshal([]byte(*in), &r); err != nil {
		log.Printf("received an unexpected error: %v\n", err)
	}
	return r
}
