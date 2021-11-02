package routes

import (
	"log"
	"strconv"
	"strings"
)

func parseTimeouts(v string) (int, error) {
	var timeout int
	var err error

	times := map[string]int{
		"s": 1,
		"m": 60,
		"h": 3600,
		"d": 86400,
	}

	v = strings.ReplaceAll(v, " ", "")

	if v == "" {
		return 0, nil
	}

	wasConvert := false
	for suffix, k := range times {
		if strings.HasSuffix(strings.ToLower(v), suffix) {
			timeout, err = strconv.Atoi(strings.TrimSuffix(v, suffix))
			timeout *= k
			wasConvert = true
			break
		}
	}
	if !wasConvert {
		timeout, err = strconv.Atoi(v)
	}
	return timeout, err
}

func ConfigureTimeouts(route *InputRoute) *InputRoute {
	aggregateTimeoutSeconds, err := parseTimeouts(route.Plugins.AggregateMessageTimeout)
	if err != nil {
		log.Printf("%q settings: Can't convert 'aggregate-message-timeout'(%q) to seconds.",
			route.Name, route.Plugins.AggregateMessageTimeout)
	}

	route.Plugins.AggregateTimeoutSeconds = aggregateTimeoutSeconds

	uniqueMessageTimeoutSeconds, err := parseTimeouts(route.Plugins.UniqueMessageTimeout)
	if err != nil {
		log.Printf("%q settings: Can't convert 'unique-message-timeout'(%q) to seconds.",
			route.Name, route.Plugins.UniqueMessageTimeout)
	}

	route.Plugins.UniqueMessageTimeoutSeconds = uniqueMessageTimeoutSeconds

	return route
}
