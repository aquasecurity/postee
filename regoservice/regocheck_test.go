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

	inputFiles := []string{"../inputFiles.rego"}
	incorrectInputFiles := []string{"../incorrectFile.rego"}
	emptyinputFiles := []string{}
	file, err := os.Create("inputFiles.rego")
	if err != nil {
		t.Errorf("error create file: %v", err)
	}
	file.WriteString(fmt.Sprintf(module, rego))
	defer os.Remove("inputFiles.rego")
	defer file.Close()
	incorrectFile, err := os.Create("incorrectFile.rego")
	if err != nil {
		t.Errorf("error create file: %v", err)
	}
	incorrectFile.WriteString(fmt.Sprintf(module, incorrectRego))
	defer os.Remove("incorrectFile.rego")
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
		{emptyRego, inputFiles, scanResult, true, false},
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
