package formatting

import (
	"bytes"
	"fmt"
	"strings"
)

type MarkdownProvider struct {}

func (mrkdwn *MarkdownProvider) TitleH2(title string) string {
	return fmt.Sprintf("## %s\n", title)
}

func (mrkdwn *MarkdownProvider) TitleH3(title string) string {
	return fmt.Sprintf("### %s\n", title)
}

func (mrkdwn *MarkdownProvider) ColourText(text, color string) string {
	return fmt.Sprintf("**%s**", text)
}

func (mrkdwn *MarkdownProvider) Table(rows [][]string) string {
	if len(rows) == 0 {
		return ""
	}
	var builder bytes.Buffer
	for i, row := range rows {
		if i == 1 {
			fmt.Fprintf( &builder, "|%s\n", strings.Repeat(" --- |", len(row)))
		}
		fmt.Fprintf( &builder, "| %s |\n", strings.Join(row, " | "))
	}
	return builder.String()
}

func (mrkdwn *MarkdownProvider) P(p string) string {
	return fmt.Sprintf("%s\n", p)
}
