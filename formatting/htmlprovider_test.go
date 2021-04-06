package formatting

import (
	"testing"
)

func TestHtmlProvider_Table(t *testing.T) {
	var tests = []tableTest{
		{
			source: [][]string{
				{"Header1", "Header2"},
				{"Field1", "Field2"},
			},
			result: `<TABLE border='1' style='width: 100%; border-collapse: collapse;'>
<TR>
<TH style='padding: 5px;'>Header1</TH><TH style='padding: 5px;'>Header2</TH>
</TR>
<TR>
<TD style='padding: 5px;'>Field1</TD><TD style='padding: 5px;'>Field2</TD>
</TR>
</TABLE>
`,
		},
	}
	tableTesting(tests, t, new(HtmlProvider))
}

func TestHtmlProviderTags(t *testing.T) {
	tests := []tagsTest{
		{
			"Lorem Ipsum",
			"red",
			"url",
			"<span style='color:red'>Lorem Ipsum</span>",
			"<h1>Lorem Ipsum</h1>\n",
			"<h2>Lorem Ipsum</h2>\n",
			"<h3>Lorem Ipsum</h3>\n",
			"<p>Lorem Ipsum</p>\n",
			"<a href='url'>Lorem Ipsum</a>",
		},
	}
	tagsTesting(tests, t, new(HtmlProvider))
}
