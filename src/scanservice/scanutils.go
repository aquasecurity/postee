package scanservice

import (
	"log"
	"regexp"
	"strings"
)

func compliesPolicies(policies []string, s string) bool {
	for _, p := range policies {
		policy := strings.ToLower(p)
		source := strings.ToLower(s)

		if strings.Contains(policy, "*") {
			policy := strings.ReplaceAll(policy, "*", ".*")
			matched, err := regexp.MatchString(policy, source)
			if err != nil {
				log.Printf("regexp.Match Error in compliesPolicies for policy %q (image: %q): %v", policy, source, err)
				continue
			}
			return matched
		}
		if strings.Contains(source, policy) {
			return true
		}
	}
	return false
}
