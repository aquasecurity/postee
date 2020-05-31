package scanservice

import "strings"

func compliesPolicies(policies []string, s string) bool {
	for _, p := range policies {
		policy := strings.ToLower(p)
		source := strings.ToLower(s)
		if strings.Contains(source, policy) {
			return true
		}
	}
	return false
}
