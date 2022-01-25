package formatting

import (
	"testing"

	"github.com/aquasecurity/postee/v2/layout"
)

type tagsTest struct {
	source                       string
	color                        string
	link                         string
	colourText, h1, h2, h3, p, a string
}

type tableTest struct {
	source [][]string
	result string
}

func tagsTesting(tests []tagsTest, t *testing.T, provider layout.LayoutProvider) {
	for _, test := range tests {
		if c := provider.ColourText(test.source, test.color); c != test.colourText {
			t.Errorf("Wrong colorur text\nWaited: %q\n Result: %q", test.colourText, c)
		}
		if h1 := provider.TitleH1(test.source); h1 != test.h1 {
			t.Errorf("Wrong H1 formatting for %q\nWaited: %q\n Result: %q", test.source, test.h1, h1)
		}
		if h2 := provider.TitleH2(test.source); h2 != test.h2 {
			t.Errorf("Wrong H2 formatting for %q\nWaited: %q\n Result: %q", test.source, test.h2, h2)
		}
		if h3 := provider.TitleH3(test.source); h3 != test.h3 {
			t.Errorf("Wrong H3 formatting for %q\nWaited: %q\n Result: %q", test.source, test.h3, h3)
		}
		if p := provider.P(test.source); p != test.p {
			t.Errorf("Wrong P formatting for %q\nWaited: %q\n Result: %q", test.source, test.p, p)
		}
		if a := provider.A(test.link, test.source); a != test.a {
			t.Errorf("Wrong P formatting for link %q (%q)\nWaited: %q\n Result: %q",
				test.link, test.source, test.a, a)
		}
	}
}

func tableTesting(tests []tableTest, t *testing.T, provider layout.LayoutProvider) {
	for _, test := range tests {
		if got := provider.Table(test.source); got != test.result {
			t.Errorf("Error: html.Table(test.Source)\nResult: %s\nWaited: %s\n", got, test.result)
		}
	}
}
