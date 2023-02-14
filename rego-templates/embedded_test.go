package rego_templates

import (
	"embed"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/aquasecurity/postee/v2/data"
)

//go:embed testdata/*.rego
var embedTest embed.FS

func TestPopulateTemplate(t *testing.T) {
	expected := map[string]string{
		"test.rego": `package test.rawmessage.json`,
	}

	actual := make(map[string]string)
	populateTemplates(embedTest, actual, "testdata")

	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("expected templates: %v, actual: %v", expected, actual)
	}
}

func TestGetAsDataTemplates(t *testing.T) {
	testData := make(map[string]string)
	populateTemplates(embedTest, testData, "testdata")

	tests := []struct {
		name     string
		input    map[string]string
		expected []data.Template
	}{
		{
			name:  "testdata",
			input: testData,
			expected: []data.Template{
				{
					Name:        "test",
					RegoPackage: "test.rawmessage.json",
				},
			},
		},
		{
			name:  "testdata",
			input: EmbeddedCommon(),
			expected: []data.Template{
				{
					Name:        "common",
					RegoPackage: "postee",
				},
				{
					Name:        "iac",
					RegoPackage: "postee",
				},
			},
		},
		{
			name:     "empty",
			input:    map[string]string{},
			expected: []data.Template{},
		},
		{
			name: "bad rego",
			input: map[string]string{
				"test.test": "packageconnected",
			},
			expected: []data.Template{},
		},
		{
			name: "bad rego 2",
			input: map[string]string{
				"test.test": "package ",
			},
			expected: []data.Template{},
		},
		{
			name: "bad rego 3",
			input: map[string]string{
				"test.test": "package",
			},
			expected: []data.Template{},
		},
		{
			name: "empty rego",
			input: map[string]string{
				"test.test": "",
			},
			expected: []data.Template{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := getAsDataTemplates(test.input)
			sort.Slice(actual, func(i, j int) bool {
				return actual[i].Name < actual[j].Name
			})
			if !reflect.DeepEqual(actual, test.expected) {
				t.Fatalf("expected data templates: %v, actual: %v", test.expected, actual)
			}
		})
	}
}

func TestEmbeddedTemplate(t *testing.T) {
	path := localDir
	files, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}

	expected := countRegoFiles(files)
	actual := len(EmbeddedTemplates())
	if actual != expected {
		t.Fatalf("for path: '%s' expected templates: %v, actual: %v", path, expected, actual)
	}

}

func TestEmbeddedCommon(t *testing.T) {
	path := commonDir
	files, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}

	expected := countRegoFiles(files)
	actual := len(EmbeddedCommon())
	if actual != expected {
		t.Fatalf("for path: '%s' expected templates: %v, actual: %v", path, expected, actual)
	}
}

func countRegoFiles(files []os.DirEntry) int {
	var count int
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		if strings.HasSuffix(f.Name(), ".rego") {
			count++
		}
	}
	return count
}
