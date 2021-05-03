package regoservice

import (
	"encoding/json"
	"testing"
)

func TestOpaRego(t *testing.T) {
	rego := `contains(input.image, "alpine")`
	regoWithoutPackage := ``

	scanResult := `{"image":"alpine:26"}`
	scanNoJson := "simple text"
	scanWithoutResult := `{"image":"1science:latest"}`

	tests := []struct {
		rules   string
		scan    string
		result  bool
		isError bool
	}{
		{rego, scanResult, true, false},
		{rego, scanNoJson, false, true},
		{rego, scanWithoutResult, false, false},
		{regoWithoutPackage, scanResult, false, true},
	}

	for _, test := range tests {
		intr := map[string]interface{} {}
		if err := json.Unmarshal([]byte(test.scan), &intr); err != nil && !test.isError {
			t.Errorf("json.Unmarshal(%q) error: %v", test.scan, err)
			continue
		}

		got, err := IsRegoCorrectInterface(intr, test.rules)
		if err != nil && !test.isError {
			t.Errorf("received an undefined error: %v", err)
			continue
		}
		if got != test.result {
			t.Errorf("isRegoCorrect(%q, %q) == %t, wanted %t", test.scan, test.rules, got, test.result)
		}
	}
}
