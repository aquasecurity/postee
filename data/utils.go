package data

import (
	"regexp"
)

func ClearField(source string) string {
	re := regexp.MustCompile(`[[:cntrl:]]|[\x{FFFD}]`)
	return re.ReplaceAllString(source, "")
}

func CopyStringArray(src []string) []string {
	dst := make([]string, len(src))
	copy(dst, src)
	return dst
}
