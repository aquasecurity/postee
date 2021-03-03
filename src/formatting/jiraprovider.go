package formatting

import (
	"bytes"
	"fmt"
	"strings"
)

type JiraLayoutProvider struct{}

func (jira *JiraLayoutProvider) P(p string) string {
	return fmt.Sprintf("%s\n", p)
}

func (jira *JiraLayoutProvider) TitleH1(title string) string {
	return fmt.Sprintf("h1. %s\n", title)
}

func (jira *JiraLayoutProvider) TitleH2(title string) string {
	return fmt.Sprintf("h2. %s\n", title)
}

func (jira *JiraLayoutProvider) TitleH3(title string) string {
	return fmt.Sprintf("h3. %s\n", title)
}

func (jira *JiraLayoutProvider) ColourText(text, color string) string {
	return fmt.Sprintf("{color:%s}%s{color}", color, text)
}

func (jira *JiraLayoutProvider) Table(rows [][]string) string {
	if len(rows) == 0 {
		return ""
	}
	var builder bytes.Buffer
	for i, row := range rows {
		if i == 0 {
			fmt.Fprintf(&builder, "||%s||\n", strings.Join(row, "||"))
		} else {
			fmt.Fprintf(&builder, "|%s|\n", strings.Join(row, "|"))
		}
	}
	builder.WriteString("\n")
	return builder.String()
}

func (jira *JiraLayoutProvider) A(url, title string) string {
	return fmt.Sprintf("[%s|%s]", title, url)
}
