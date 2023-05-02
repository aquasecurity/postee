package regoservice

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io/fs"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"testing"
)

var (
	regoHtml = `
package rego1
title:="Audit event received"
result:=sprintf("Audit event received from %s", [input.user])	
url:="Audit-registry-received/Audit-image-received"
`
	regoJson = `
package rego1
title:="Audit event received"
result:={
	"assignee": input.user
}
url:="Audit-registry-received/Audit-image-received"
`
	regoJsonWithoutUrl = `
package rego1
title:="Audit event received"
result:={
	"assignee": input.user
}
`
	regoWithoutResult = `
package rego1
ttle:="Audit event received"
`
	regoWithoutAnyExpression = `
package rego1
`
	regoServiceNowSimpleExample = `
package rego1
title:="test title"
result = "test description"

result_date = 1667725398
result_category = "test category"
result_subcategory = "test subcategory"
result_assigned_group = "test assigned group"

result_severity := 1

result_summary := "test summary"
`
	invalidRego = `
package rego1
default input = false
`

	regoHtmlWithComplexPackage = `
package postee.rego1
title:="Audit event received"
result:=sprintf("Audit event received from %s", [input.user])	
url:="Audit-registry-received/Audit-image-received"
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
		regoRule          *string
		caseDesc          string
		input             *string
		regoPackage       string
		expectedValues    map[string]string
		shouldEvalFail    bool
		shouldPrepareFail bool
		skipBuildin       bool
		skipExternal      bool
	}{
		{
			regoRule:    &regoHtml,
			caseDesc:    "simple case producing html output",
			input:       &input,
			regoPackage: "rego1",
			expectedValues: map[string]string{
				"title":       "Audit event received",
				"description": "Audit event received from demo",
				"url":         "Audit-registry-received/Audit-image-received",
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
				"url":         "Audit-registry-received/Audit-image-received",
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
				"url":         "Audit-registry-received/Audit-image-received",
			},
		},
		{
			regoRule:    &regoJsonWithoutUrl,
			caseDesc:    "producing json output",
			input:       &input,
			regoPackage: "rego1",
			expectedValues: map[string]string{
				"title":       "Audit event received",
				"description": `{"assignee":"demo"}`,
				"url":         "",
			},
		},
		{
			regoRule:    &regoServiceNowSimpleExample,
			caseDesc:    "producing ServiceNow output",
			input:       &input,
			regoPackage: "rego1",
			expectedValues: map[string]string{
				"title":         "test title",
				"description":   "test description",
				"date":          "1667725398",
				"severity":      "1",
				"summary":       "test summary",
				"category":      "test category",
				"subcategory":   "test subcategory",
				"assignedGroup": "test assigned group",
			},
		},
		/* cases which should fail are below*/
		{
			regoRule:          &regoWithoutResult,
			caseDesc:          "Rego with wrong package specified",
			input:             &input,
			regoPackage:       "rego3",
			expectedValues:    map[string]string{},
			shouldPrepareFail: true,
			skipExternal:      true,
		},
		{
			regoRule:       &regoWithoutAnyExpression,
			caseDesc:       "Rego without any expression",
			input:          &input,
			regoPackage:    "rego1",
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
	}
	for _, test := range tests {
		if !test.skipBuildin {
			evaluateBuildinRego(t, test.caseDesc, test.regoRule, test.input, test.regoPackage, test.expectedValues, test.shouldEvalFail, test.shouldPrepareFail)
		}

		if !test.skipExternal {
			evaluateExternalRego(t, test.caseDesc, test.regoRule, test.input, test.regoPackage, test.expectedValues, test.shouldEvalFail, test.shouldPrepareFail)
		}
	}
}

func evaluateBuildinRego(t *testing.T, caseDesc string, regoRule *string, input *string, regoPackage string, expectedValues map[string]string, shouldEvalFail bool, shouldPrepareFail bool) {
	buildinRegoTemplatesSaved := buildinRegoTemplates
	testRego := "rego1.rego"
	buildinRegoTemplates = []string{testRego}

	errWrite := ioutil.WriteFile(testRego, []byte(*regoRule), 0644)
	if errWrite != nil {
		t.Fatal(errWrite)
	}

	defer func() {
		buildinRegoTemplates = buildinRegoTemplatesSaved
		os.Remove(testRego)
	}()
	demo, err := BuildBundledRegoEvaluator(regoPackage)
	if err != nil && !shouldPrepareFail {
		t.Errorf("[%s] received an unexpected error while preparing query: %v\n", caseDesc, err)
		return
	}
	if err == nil && shouldPrepareFail {
		t.Errorf("test case [%s] should fail on prepare\n", caseDesc)
	}

	if shouldPrepareFail {
		return
	}

	if demo.IsAggregationSupported() {
		t.Errorf("[%s] rule shouldn't support aggregation", caseDesc)
	}
	r, err := demo.Eval(parseJson(input), "")
	if err != nil && !shouldEvalFail {
		t.Errorf("[%s] unexpected error received while evaluating query: %v\n", caseDesc, err)
	}
	if err == nil && shouldEvalFail {
		t.Errorf("test case [%s] should fail on eval\n", caseDesc)
	}

	for key, expected := range expectedValues {
		if r[key] != expected {
			t.Errorf("[%s] Incorrect %s: expected %s, got %s\n", caseDesc, key, expected, r[key])
		}

	}
}
func evaluateExternalRego(t *testing.T, caseDesc string, regoRule *string, input *string, regoPackage string, expectedValues map[string]string, shouldEvalFail bool, shouldPrepareFail bool) {
	commonRegoTemplatesSaved := commonRegoTemplates
	testRego := "rego1.rego"
	commonRegoFilename := "common.rego"
	commonRegoTemplates = []string{commonRegoFilename}

	err := ioutil.WriteFile(commonRegoFilename, []byte(commonRego), 0644)
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		commonRegoTemplates = commonRegoTemplatesSaved
		os.Remove(commonRegoFilename)
	}()

	demo, err := BuildExternalRegoEvaluator(testRego, *regoRule)
	if err != nil && !shouldPrepareFail {
		t.Errorf("[%s] received an unexpected error while preparing query: %v\n", caseDesc, err)
		return
	}
	if err == nil && shouldPrepareFail {
		t.Errorf("test case [%s] should fail on prepare\n", caseDesc)
	}

	if shouldPrepareFail {
		return
	}
	if demo.IsAggregationSupported() {
		t.Errorf("[%s] rule shouldn't support aggregation", caseDesc)
	}
	r, err := demo.Eval(parseJson(input), "")
	if err != nil && !shouldEvalFail {
		t.Errorf("[%s] unexpected error received while evaluating query: %v\n", caseDesc, err)
	}
	if err == nil && shouldEvalFail {
		t.Errorf("test case [%s] should fail on eval\n", caseDesc)
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

func TestBuildBundledRegoForPackage(t *testing.T) {
	tests := []struct {
		name      string
		fileName  string
		perm      fs.FileMode
		wantRules bool
		wantErr   string
	}{
		{
			name:      "happy path",
			fileName:  "rego1.rego",
			perm:      0644,
			wantRules: true,
		},
		{
			name:     "bad permission",
			fileName: "rego1.rego",
			perm:     0000,
			wantErr:  "permission denied",
		},
		{
			name:     "lost+found",
			fileName: "lost+found",
			perm:     0644,
		},
		{
			name:     "lost+found with bad permission",
			fileName: "lost+found",
			perm:     0000,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regoFilePath := filepath.Join(t.TempDir(), tt.fileName)
			err := os.WriteFile(regoFilePath, []byte(regoHtml), tt.perm)
			require.NoError(t, err)

			savedBuildinRegoTemplates := buildinRegoTemplates
			buildinRegoTemplates = []string{regoFilePath}
			defer func() {
				buildinRegoTemplates = savedBuildinRegoTemplates
			}()

			r, err := buildBundledRegoForPackage("rego1")
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}

			if tt.wantRules {
				assert.NotEmpty(t, r.Modules())
				return
			}

			assert.Empty(t, r.Modules())

		})
	}
}
