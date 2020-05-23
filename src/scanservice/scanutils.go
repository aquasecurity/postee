package scanservice

import "strings"

func compliesPolicies(policies []string, source string) bool {
	for _, policy := range policies {
		if strings.Contains(source, policy) {
			return true
		}
	}
	return false
}
