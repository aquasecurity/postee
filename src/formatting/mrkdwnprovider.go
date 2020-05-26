package formatting

import (
	"bytes"
	"fmt"
	"strings"
)

type MrkdwnProvider struct {}

func (mrkdwn *MrkdwnProvider) TitleH2(title string) string {
	return fmt.Sprintf("## %s\n", title)
}

func (mrkdwn *MrkdwnProvider) TitleH3(title string) string {
	return fmt.Sprintf("### %s\n", title)
}

func (mrkdwn *MrkdwnProvider) ColourText(text, color string) string {
	return fmt.Sprintf("**%s**", text)
}

func (mrkdwn *MrkdwnProvider) Table(rows [][]string) string {
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
	builder.WriteString("\n")
	return builder.String()
}

func (mrkdwn *MrkdwnProvider) P(p string) string {
	return fmt.Sprintf("%s\n", p)
}
