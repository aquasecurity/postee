package jiraformatting

import (
	"fmt"
	"regexp"
	"strings"
)

func RenderTableTitle( titles []string) string {
	return fmt.Sprintf("||%s||\n", strings.Join(titles, "||"))
}

func RenderTableRow( fields []string) string {
	return fmt.Sprintf("|%s|\n", strings.Join(fields, "|"))
}

func RenderColourIntField(data int, color string) string {
	return fmt.Sprintf("{color:%s}%d{color}", color, data)
}

func ClearField(source string) string {
	re := regexp.MustCompile(`[[:cntrl:]]|[\x{FFFD}]`)
	return re.ReplaceAllString(source, "")
}

