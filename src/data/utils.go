package data

import (
	"regexp"
	"strings"
)

var (
	SeverityPriorities = map[string]int{
		"critical":5,
		"high":4,
		"medium":3,
		"low":2,
		"negligible":1,
	}
)

func ClearField(source string) string {
	re := regexp.MustCompile(`[[:cntrl:]]|[\x{FFFD}]`)
	return re.ReplaceAllString(source, "")
}

func copyResources(dst, src []InfoResources)  {
	copy(dst, src)
}

func (scan *ScanImageInfo) GetCopyOfResources() []InfoResources {
	result := make([]InfoResources, len(scan.Resources))
	copyResources(result, scan.Resources)
	return result
}

func (scan *ScanImageInfo) SetCopyOfResources(base []InfoResources) {
	scan.Resources = make([]InfoResources, len(base))
	copyResources(scan.Resources, base)
}

func (scan *ScanImageInfo) RemoveLowLevelVulnerabilities(maxLevel string) {
	min := SeverityPriorities[strings.ToLower(maxLevel)]
	for r:=0; r<len(scan.Resources); r++ {
		for i:= len(scan.Resources[r].Vulnerabilities)-1; i >= 0; i-- {
			currentPriority := SeverityPriorities[strings.ToLower(scan.Resources[r].Vulnerabilities[i].Severity)]
			if currentPriority < min {
				scan.Resources[r].Vulnerabilities =
					append(
						scan.Resources[r].Vulnerabilities[:i],
						scan.Resources[r].Vulnerabilities[i+1:]...)
			}
		}
	}
}
