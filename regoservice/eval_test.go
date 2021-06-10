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
	regoJson = `
package rego1
title:="Audit event received"
result:={
	"assignee": input.user
}
`
	regoNumber = `
package rego1
title:="Audit event received"
result:=5
`

	regoWithoutResult = `
package rego1
ttle:="Audit event received"
`
	regoWithoutAnyExpression = `
package rego1
`
	invalidRego = `
package rego1
default input = false
`

	regoHtmlWithComplexPackage = `
package postee.rego1
title:="Audit event received"
result:=sprintf("Audit event received from %s", [input.user])	
`

	input = `{
		"user": "demo"
	}
`
	commonRego = `package postee
flat_array(a) = o {
	o:=[item |
		item:=a[_][_]
	]
}	
`
)

func TestEval(t *testing.T) {
	tests := []struct {
		regoRule       *string
		caseDesc       string
		input          *string
		regoPackage    string
		expectedValues map[string]string
		shouldEvalFail bool
	}{
		{
			regoRule:    &regoHtml,
			caseDesc:    "simple case producing html output",
			input:       &input,
			regoPackage: "rego1",
			expectedValues: map[string]string{
				"title":       "Audit event received",
				"description": "Audit event received from demo",
			},
		},
		{
			regoRule:    &regoHtmlWithComplexPackage,
			caseDesc:    "Multilevel package",
			input:       &input,
			regoPackage: "postee.rego1",
			expectedValues: map[string]string{
				"title":       "Audit event received",
				"description": "Audit event received from demo",
			},
		},
		{
			regoRule:    &regoJson,
			caseDesc:    "producing json output",
			input:       &input,
			regoPackage: "rego1",
			expectedValues: map[string]string{
				"title":       "Audit event received",
				"description": `{"assignee":"demo"}`,
			},
		},
		{
			regoRule:       &regoWithoutResult,
			caseDesc:       "Rego without result expression",
			input:          &input,
			regoPackage:    "rego1",
			expectedValues: map[string]string{},
			shouldEvalFail: true,
		},
		{
			regoRule:       &regoWithoutAnyExpression,
			caseDesc:       "Rego without any expression",
			input:          &input,
			regoPackage:    "rego1",
			expectedValues: map[string]string{},
			shouldEvalFail: true,
		},
		{
			regoRule:       &invalidRego,
			caseDesc:       "Invalid Rego",
			input:          &input,
			regoPackage:    "rego1",
			expectedValues: map[string]string{},
			shouldEvalFail: true,
		},
		{
			regoRule:       &regoNumber,
			caseDesc:       "Rego returned number",
			input:          &input,
			regoPackage:    "rego1",
			expectedValues: map[string]string{},
			shouldEvalFail: true,
		},
	}
	for _, test := range tests {
		evaluateBuildinRego(t, test.caseDesc, test.regoRule, test.input, test.regoPackage, test.expectedValues, test.shouldEvalFail)
		evaluateExternalRego(t, test.caseDesc, test.regoRule, test.input, test.regoPackage, test.expectedValues, test.shouldEvalFail)
	}
}

func evaluateBuildinRego(t *testing.T, caseDesc string, regoRule *string, input *string, regoPackage string, expectedValues map[string]string, shouldEvalFail bool) {
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
		t.Fatalf("[%s] received an unexpected error while preparing query: %v\n", caseDesc, err)
	}
	if demo.IsAggregationSupported() {
		t.Errorf("[%s] rule shouldn't support aggregation", caseDesc)
	}
	r, err := demo.Eval(parseJson(input), "")
	if err != nil && shouldEvalFail {
		t.Fatalf("[%s] unexpected error received while evaluating query: %v\n", caseDesc, err)
	}

	for key, expected := range expectedValues {
		if r[key] != expected {
			t.Errorf("[%s] Incorrect %s: expected %s, got %s\n", caseDesc, key, expected, r[key])
		}

	}
}
func evaluateExternalRego(t *testing.T, caseDesc string, regoRule *string, input *string, regoPackage string, expectedValues map[string]string, shouldEvalFail bool) {
	commonRegoTemplatesSaved := commonRegoTemplates
	testRego := "rego1.rego"
	commonRegoFilename := "common.rego"
	commonRegoTemplates = []string{commonRegoFilename}

	ioutil.WriteFile(commonRegoFilename, []byte(commonRego), 0644)

	defer func() {
		commonRegoTemplates = commonRegoTemplatesSaved
		os.Remove(commonRegoFilename)
	}()

	demo, err := BuildExternalRegoEvaluator(testRego, *regoRule)
	if err != nil {
		t.Fatalf("[%s] received an unexpected error while preparing query: %v\n", caseDesc, err)
	}
	if demo.IsAggregationSupported() {
		t.Errorf("[%s] rule shouldn't support aggregation", caseDesc)
	}
	r, err := demo.Eval(parseJson(input), "")
	if err != nil && !shouldEvalFail {
		t.Fatalf("[%s] unexpected error received while evaluating query: %v\n", caseDesc, err)
	}

	for key, expected := range expectedValues {
		if r[key] != expected {
			t.Errorf("[%s] Incorrect %s: expected %s, got %s\n", caseDesc, key, expected, r[key])
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
