package data

import (
	"regexp"
)

func ClearField(source string) string {
	re := regexp.MustCompile(`[[:cntrl:]]|[\x{FFFD}]`)
	return re.ReplaceAllString(source, "")
}
