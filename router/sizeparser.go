package router

import (
	"log"
	"regexp"
	"strconv"
	"strings"
)

const (
	B  = 1
	KB = 1024
	MB = 1024 * KB
	GB = 1024 * MB
)

var (
	sizeRegex = regexp.MustCompile(`^(\d+) ?([kKmMgG]?[bB]?)$`)
	suffixes  = map[string]int{"b": B, "kb": KB, "mb": MB, "gb": GB}

	parseError = "unable parse MaxDBSize, unlimited size used"
)

func parseSize(sizeStr string) int {
	if sizeStr == "" {
		return 0
	}

	matches := sizeRegex.FindStringSubmatch(sizeStr)

	if matches != nil {
		size, err := strconv.Atoi(matches[1])
		if err != nil {
			log.Println(parseError)
			return 0
		}
		if matches[2] != "" {
			suffix := suffixes[strings.ToLower(matches[2])]
			return size * suffix
		} else {
			return size
		}
	} else {
		log.Println(parseError)
		return 0
	}
}
