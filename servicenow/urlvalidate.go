package servicenow_api

import (
	"net/url"
	"regexp"
	"strings"
)

// IsValidURL returns true when the URL is valid: parseable, scheme "http" or "https", and non-empty host.
func IsValidURL(URL string) bool {
	u, err := url.ParseRequestURI(URL)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	if u.Host == "" {
		return false
	}
	return true
}

var localhostURLPattern = regexp.MustCompile(`^http://localhost|^https://localhost|^localhost|127\.0\.0\.1|\[::\]`)

// IsUrlNotLocalhost returns true when the URL does not refer to localhost (or 127.0.0.1, [::]).
// Used to reject localhost URLs for ServiceNow instance URL.
func IsUrlNotLocalhost(URL string) bool {
	return !localhostURLPattern.MatchString(strings.ToLower(URL))
}
