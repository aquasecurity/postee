package regoservice

import (
	"encoding/json"
	"flag"
	"github.com/stretchr/testify/require"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "update golden files")

func TestEval(t *testing.T) {
	tests := []struct {
		regoRule                *string
		templateFile            string
		caseDesc                string
		inputFile               string
		regoPackage             string
		expectedValues          map[string]string // Description will save in golden file
		expectedDescriptionFile string
		shouldEvalFail          bool
		shouldPrepareFail       bool
		skipBuildin             bool
		skipExternal            bool
	}{
		/* cases for basic functionality */
		{
			caseDesc:                "simple case producing html output",
			inputFile:               "testdata/inputs/simple-input.json",
			templateFile:            "testdata/templates/html.rego",
			regoPackage:             "rego1",
			expectedDescriptionFile: "testdata/goldens/html.golden",
			expectedValues: map[string]string{
				"title": "Audit event received",
				"url":   "Audit-registry-received/Audit-image-received",
			},
		},
		{
			caseDesc:                "Multilevel package",
			inputFile:               "testdata/inputs/simple-input.json",
			templateFile:            "testdata/templates/html-with-complex-pkg.rego",
			regoPackage:             "postee.rego1",
			expectedDescriptionFile: "testdata/goldens/html-with-complex-pkg.golden",
			expectedValues: map[string]string{
				"title": "Audit event received",
				"url":   "Audit-registry-received/Audit-image-received",
			},
		},
		{
			caseDesc:                "producing json output",
			inputFile:               "testdata/inputs/simple-input.json",
			templateFile:            "testdata/templates/json.rego",
			regoPackage:             "rego1",
			expectedDescriptionFile: "testdata/goldens/json.golden",
			expectedValues: map[string]string{
				"title": "Audit event received",
				"url":   "Audit-registry-received/Audit-image-received",
			},
		},
		{
			caseDesc:                "producing json output without url",
			inputFile:               "testdata/inputs/simple-input.json",
			templateFile:            "testdata/templates/json-without-url.rego",
			regoPackage:             "rego1",
			expectedDescriptionFile: "testdata/goldens/json-without-url.golden",
			expectedValues: map[string]string{
				"title": "Audit event received",
				"url":   "",
			},
		},
		{
			caseDesc:                "producing ServiceNow output",
			inputFile:               "testdata/inputs/simple-input.json",
			templateFile:            "testdata/templates/servicenow.rego",
			expectedDescriptionFile: "testdata/goldens/servicenow.golden",
			regoPackage:             "rego1",
			expectedValues: map[string]string{
				"title":         "test title",
				"date":          "1667725398",
				"severity":      "1",
				"summary":       "test summary",
				"category":      "test category",
				"subcategory":   "test subcategory",
				"assignedGroup": "test assigned group",
			},
		},
		/* cases for templates from `rego-templates` directory */
		{
			caseDesc:     "raw-message-html.rego template",
			inputFile:    "testdata/inputs/simple-input.json",
			templateFile: "../rego-templates/raw-message-html.rego",
			regoPackage:  "postee.rawmessage.html",
			expectedValues: map[string]string{
				"title": "Raw Message Received",
			},
			expectedDescriptionFile: "testdata/goldens/raw-message-html.golden",
		},
		/* cases which should fail are below*/
		{
			caseDesc:          "Rego with wrong package specified",
			inputFile:         "testdata/inputs/simple-input.json",
			templateFile:      "testdata/templates/without-result.rego",
			regoPackage:       "rego3",
			expectedValues:    map[string]string{},
			shouldPrepareFail: true,
			skipExternal:      true,
		},
		{
			caseDesc:       "Rego without any expression",
			inputFile:      "testdata/inputs/simple-input.json",
			templateFile:   "testdata/templates/without-any-expression.rego",
			regoPackage:    "rego1",
			shouldEvalFail: true,
		},
		{
			caseDesc:       "Invalid Rego",
			inputFile:      "testdata/inputs/simple-input.json",
			templateFile:   "testdata/templates/invalid.rego",
			regoPackage:    "rego1",
			expectedValues: map[string]string{},
			shouldEvalFail: true,
		},
	}
	for _, test := range tests {
		t.Run(test.caseDesc, func(t *testing.T) {
			if !test.skipBuildin {
				evaluateBuildinRego(t, test.caseDesc, test.inputFile, test.templateFile, test.expectedDescriptionFile, test.regoPackage, test.expectedValues, test.shouldEvalFail, test.shouldPrepareFail)
			}

			if !test.skipExternal {
				evaluateExternalRego(t, test.caseDesc, test.inputFile, test.templateFile, test.expectedDescriptionFile, test.expectedValues, test.shouldEvalFail, test.shouldPrepareFail)
			}
		})
	}
}

func evaluateBuildinRego(t *testing.T, caseDesc, inputFile, templateFile, descriptionGoldenFile, regoPackage string, expectedValues map[string]string, shouldEvalFail bool, shouldPrepareFail bool) {
	buildinRegoTemplatesSaved := buildinRegoTemplates
	buildinRegoTemplates = []string{templateFile}
	defer func() {
		buildinRegoTemplates = buildinRegoTemplatesSaved
	}()

	demo, err := BuildBundledRegoEvaluator(regoPackage)
	if shouldPrepareFail {
		require.Error(t, err, "test case should fail on prepare")
		return
	}
	require.NoError(t, err)

	if demo.IsAggregationSupported() {
		t.Errorf("[%s] rule shouldn't support aggregation", caseDesc)
	}

	f, err := os.Open(inputFile)
	require.NoError(t, err)
	defer f.Close()

	in := make(map[string]interface{})
	err = json.NewDecoder(f).Decode(&in)
	require.NoError(t, err)

	r, err := demo.Eval(in, "")
	if shouldEvalFail {
		require.Error(t, err, "test case should fail on eval")
		return
	}
	require.NoError(t, err)

	// write description in file
	descriptionFile := filepath.Join(t.TempDir(), "description.txt")
	if *update {
		descriptionFile = descriptionGoldenFile
	}

	err = os.WriteFile(descriptionFile, []byte(r["description"]), 0644)
	require.NoError(t, err)

	compareDescriptions(t, descriptionGoldenFile, descriptionFile)

	for key, expected := range expectedValues {
		want := r[key]
		require.EqualValues(t, expected, want)
	}
}
func evaluateExternalRego(t *testing.T, caseDesc, inputFile, templateFile, descriptionGoldenFile string, expectedValues map[string]string, shouldEvalFail bool, shouldPrepareFail bool) {
	commonRegoTemplatesSaved := commonRegoTemplates
	commonRegoTemplates = []string{"testdata/templates/common/common.rego"}
	defer func() {
		commonRegoTemplates = commonRegoTemplatesSaved
	}()

	b, err := os.ReadFile(templateFile)
	require.NoError(t, err)

	demo, err := BuildExternalRegoEvaluator(templateFile, string(b))
	if shouldPrepareFail {
		require.Error(t, err, "test case should fail on prepare")
		return
	}
	require.NoError(t, err)

	if demo.IsAggregationSupported() {
		t.Errorf("[%s] rule shouldn't support aggregation", caseDesc)
	}

	f, err := os.Open(inputFile)
	require.NoError(t, err)
	defer f.Close()

	in := make(map[string]interface{})
	err = json.NewDecoder(f).Decode(&in)
	require.NoError(t, err)

	r, err := demo.Eval(in, "")
	if shouldEvalFail {
		require.Error(t, err, "test case should fail on eval")
		return
	}
	require.NoError(t, err)

	// write description in file
	descriptionFile := filepath.Join(t.TempDir(), "description.txt")
	if *update {
		descriptionFile = descriptionGoldenFile
	}

	err = os.WriteFile(descriptionFile, []byte(r["description"]), 0644)
	require.NoError(t, err)

	compareDescriptions(t, descriptionGoldenFile, descriptionFile)

	for key, expected := range expectedValues {
		want := r[key]
		require.EqualValues(t, expected, want)
	}
}

func compareDescriptions(t *testing.T, expectedFile, gotFile string) {
	expected, err := os.ReadFile(expectedFile)
	require.NoError(t, err)
	got, err := os.ReadFile(gotFile)
	require.NoError(t, err)

	require.Equal(t, expected, got)
}

func TestBuildBundledRegoForPackage(t *testing.T) {
	regoRule := `
package rego1
title:="Audit event received"
result:=sprintf("Audit event received from %s", [input.user])	
url:="Audit-registry-received/Audit-image-received"
`
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
			err := os.WriteFile(regoFilePath, []byte(regoRule), tt.perm)
			require.NoError(t, err)

			savedBuildinRegoTemplates := buildinRegoTemplates
			buildinRegoTemplates = []string{regoFilePath}
			defer func() {
				buildinRegoTemplates = savedBuildinRegoTemplates
			}()

			r, err := buildBundledRegoForPackage("rego1")
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			if tt.wantRules {
				require.NotEmpty(t, r.Modules())
				return
			}

			require.Empty(t, r.Modules())

		})
	}
}
