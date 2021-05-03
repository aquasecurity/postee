package regoservice

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestOpaRego(t *testing.T) {
	realFile := "opa.rego"
	rego := `package postee
default allow = false
allow {
    contains(input.image, "alpine")
}`

	if err := ioutil.WriteFile(realFile, []byte(rego), 0666); err != nil {
		t.Errorf("Can't create a demo file (%q) with rego policy: %v", realFile, err)
		return
	}
	defer os.RemoveAll(realFile)

	wrongfile := "wrongfile"
	norego := "just info"
	if err := ioutil.WriteFile(wrongfile, []byte(norego), 0666); err != nil {
		t.Errorf("Can't create a demo file (%q) with rego policy: %v", realFile, err)
		return
	}
	defer os.RemoveAll(wrongfile)

	regoWithoutPackage := `package exaplle
`
	withoutPackage := "wrongfile"
	if err := ioutil.WriteFile(withoutPackage, []byte(regoWithoutPackage), 0666); err != nil {
		t.Errorf("Can't create a demo file (%q) with rego policy: %v", realFile, err)
		return
	}
	defer os.RemoveAll(withoutPackage)

	scanResult := `{"image":"alpine:26"}`
	scanNoJson := "simple text"
	scanWithoutResult := `{"image":"1science:latest"}`

	tests := []struct {
		files   []string
		scan    string
		result  bool
		isError bool
	}{
		{[]string{realFile}, scanResult, true, false},
		{[]string{wrongfile}, scanResult, false, true},
		{[]string{realFile}, scanNoJson, false, true},
		{[]string{realFile}, scanWithoutResult, false, false},
		{[]string{withoutPackage}, scanResult, false, false},
	}

	for _, test := range tests {
		got, err := IsRegoCorrectInterface(test.files, test.scan)
		if err != nil && !test.isError {
			t.Errorf("received an undefined error: %v", err)
			continue
		}
		if got != test.result {
			t.Errorf("isRegoCorrect(%v, %q) == %T, wanted %T", test.files, test.scan, got, test.result)
		}
	}
}
