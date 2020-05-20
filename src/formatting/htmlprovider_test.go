package formatting

import (
	"testing"
)

func TestHtmlProvider_Table(t *testing.T) {
	var tests = []struct {
		Source [][]string
		Result string
	}{
		{
			Source: [][]string{
				{"Header1", "Header2",},
				{"Field1", "Field2",},
			},
			Result:"<TABLE>\n<TR>\n<TH>Header1</TH><TH>Header2</TH>\n</TR>\n<TR>\n<TD>Field1</TD><TD>Field2</TD>\n</TR>\n</TABLE>\n",
		},
	}

	for _, test := range tests {
		html := new(HtmlProvider)
		if got := html.Table(test.Source); got != test.Result {
			t.Errorf("Error: html.Table(test.Source)\nResult: %s\nWaiting: %s\n", got, test.Result)

		}
	}
}
