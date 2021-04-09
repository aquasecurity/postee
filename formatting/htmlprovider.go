package formatting

import (
	"bytes"
	"fmt"
	"strings"
)

type HtmlProvider struct{}

func (html *HtmlProvider) P(p string) string {
	return fmt.Sprintf("<p>%s</p>\n", p)
}

func (html *HtmlProvider) TitleH1(title string) string {
	return fmt.Sprintf("<h1>%s</h1>\n", title)
}

func (html *HtmlProvider) TitleH2(title string) string {
	return fmt.Sprintf("<h2>%s</h2>\n", title)
}

func (html *HtmlProvider) TitleH3(title string) string {
	return fmt.Sprintf("<h3>%s</h3>\n", title)
}

func (html *HtmlProvider) ColourText(text, color string) string {
	return fmt.Sprintf("<span style='color:%s'>%s</span>", color, text)
}

func (html *HtmlProvider) Table(rows [][]string) string {
	table := make([]string, 0)
	table = append(table, "<TABLE border='1' style='width: 100%; border-collapse: collapse;'>")
	for i, r := range rows {
		var tag string
		if i == 0 {
			tag = "TH"
		} else {
			tag = "TD"
		}
		table = append(table, "<TR>")
		var rowBuilder bytes.Buffer
		for _, field := range r {
			rowBuilder.WriteString(fmt.Sprintf("<%s style='padding: 5px;'>%s</%s>", tag, field, tag))
		}
		table = append(table, rowBuilder.String())
		table = append(table, "</TR>")
	}

	table = append(table, "</TABLE>\n")
	return strings.Join(table, "\n")
}

func (html *HtmlProvider) A(url, title string) string {
	return fmt.Sprintf("<a href='%s'>%s</a>", url, title)
}
