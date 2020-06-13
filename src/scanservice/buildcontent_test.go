package scanservice

import (
	"formatting"
	"strings"
	"testing"
)

var (
	lay = new(formatting.HtmlProvider)
)

func TestBuildAggregatedContent(t *testing.T)  {
	wantBody := `<h1>title1</h1>
<p>description1</p>
<h1>title2</h1>
<p>description2</p>
`
	wantTitle := "Vulnerability scan report"

	result := buildAggregatedContent([]map[string]string{scan1, scan2}, lay)
	if !strings.HasPrefix(result["title"], wantTitle) {
		t.Errorf("Wrong Title don't contain names\nResult: %q\nWaited: %q", result["title"], wantTitle)
	}

	if result["description"] != wantBody {
		t.Errorf("Wrong Description\nResult: %q\nWaited: %q", result["description"], wantBody)
	}
}

func TestBuildMapContent(t *testing.T) {
	tests := [...]struct{
		title string
		descr string
		url   string
		want  map[string]string
	}{
		{
			"title1", "description1", "url1",
			scan1,
		},
		{
			"title2", "description2", "url2",
			scan2,
		},
	}

	for _, test := range tests {
		result := buildMapContent(test.title, lay.P(test.descr), test.url)
		if len(result) != len(test.want) {
			t.Errorf("Wrong result size\nResult: %v\nWaited: %v", result, test.want)
			continue
		}
		for k, v := range result {
			if test.want[k] != v {
				t.Errorf("Wrong title\nResult: %q\nWaited: %q", v, test.want[k])
			}
		}
	}
}

