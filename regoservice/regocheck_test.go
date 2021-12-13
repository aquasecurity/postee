package regoservice

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func TestOpaRego(t *testing.T) {
	rego := `contains(input.image, "alpine")`
	incorrectRego := `default input = false`
	emptyRego := ""

	correctInputFiles := []string{"../correctInputFiles.rego"}
	incorrectInputFiles := []string{"../incorrectInputFiles.rego"}
	emptyinputFiles := []string{}
	correctFile, err := os.Create("correctInputFiles.rego")
	if err != nil {
		t.Errorf("error create file: %v", err)
	}
	_, err = correctFile.WriteString(fmt.Sprintf(module, rego))
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove("correctInputFiles.rego")
	defer correctFile.Close()
	incorrectFile, err := os.Create("incorrectInputFiles.rego")
	if err != nil {
		t.Errorf("error create file: %v", err)
	}
	_, err = incorrectFile.WriteString(fmt.Sprintf(module, incorrectRego))
	if err != nil {
		t.Errorf("error create file: %v", err)
	}
	defer os.Remove("incorrectInputFiles.rego")
	defer incorrectFile.Close()

	scanResult := `{"image":"alpine:26"}`
	scanNoJson := "simple text"
	scanWithoutResult := `{"image":"1science:latest"}`

	tests := []struct {
		rules              string
		inputFiles         []string
		scan               string
		result             bool
		shouldTriggerError bool
	}{
		{rego, emptyinputFiles, scanResult, true, false},
		{rego, emptyinputFiles, scanNoJson, false, true},
		{rego, emptyinputFiles, scanWithoutResult, false, false},
		{emptyRego, correctInputFiles, scanResult, true, false},
		{emptyRego, incorrectInputFiles, scanNoJson, false, true},
		{emptyRego, emptyinputFiles, scanWithoutResult, true, false},
		{incorrectRego, emptyinputFiles, scanResult, false, true},
		{emptyRego, emptyinputFiles, scanResult, true, false},
	}

	for _, test := range tests {
		intr := map[string]interface{}{}
		if err := json.Unmarshal([]byte(test.scan), &intr); err != nil && !test.shouldTriggerError {
			t.Errorf("json.Unmarshal(%q) error: %v", test.scan, err)
			continue
		}

		got, err := DoesMatchRegoCriteria(intr, test.inputFiles, test.rules)
		if err != nil && !test.shouldTriggerError {
			t.Errorf("received an unexpected error: %v", err)
			continue
		}
		if got != test.result {
			t.Errorf("DoesMatchRegoCriteria(%q, %q, %q) == %t, wanted %t", test.scan, test.inputFiles, test.rules, got, test.result)
		}
	}
}

func TestGetFilesWithPathToRegoFilters(t *testing.T) {
	oldEnv := os.Getenv("REGO_FILTERS_PATH")
	defer os.Setenv("REGO_FILTERS_PATH", oldEnv)
	oldPathToRegoFilters := pathToRegoFilters

	tests := []struct {
		files         []string
		env           string
		expectedfiles []string
	}{
		{[]string{"policy.rego", "ignore.rego"}, "", []string{"rego-filters/policy.rego", "rego-filters/ignore.rego"}},
		{[]string{"policy.rego", "ignore.rego"}, "filters", []string{"filters/policy.rego", "filters/ignore.rego"}},
		{[]string{"policy.rego", "ignore.rego"}, "filters/regofiles", []string{"filters/regofiles/policy.rego", "filters/regofiles/ignore.rego"}},
		{[]string{"policy.rego", "ignore.rego"}, "/filters/regofiles", []string{"/filters/regofiles/policy.rego", "/filters/regofiles/ignore.rego"}},
		{[]string{}, "./rego", []string{}},
	}

	for _, test := range tests {
		pathToRegoFilters = ""
		os.Setenv("REGO_FILTERS_PATH", test.env)
		fmt.Println(pathToRegoFilters)
		filesWithPath := getFilesWithPathToRegoFilters(test.files)

		for i := range test.expectedfiles {
			if test.expectedfiles[i] != filesWithPath[i] {
				t.Errorf("Error for env: %s\n expected file: %s, got: %s", test.env, test.expectedfiles[i], filesWithPath[i])
			}
		}
	}

	pathToRegoFilters = oldPathToRegoFilters
}
