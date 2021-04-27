package alertmgr

import (
	"github.com/aquasecurity/postee/routes"
	"log"
	"strconv"
	"strings"
)

func buildRoute(route *routes.InputRoutes) *routes.InputRoutes {
	var timeout int
	var err error

	times := map[string]int{
		"s": 1,
		"m": 60,
		"h": 3600,
	}

	if len(route.AggregateIssuesTimeout) > 0 {
		wasConvert := false
		for suffix, k := range times {
			if strings.HasSuffix(strings.ToLower(route.AggregateIssuesTimeout), suffix) {
				timeout, err = strconv.Atoi(strings.TrimSuffix(route.AggregateIssuesTimeout, suffix))
				timeout *= k
				wasConvert = true
				break
			}
		}
		if !wasConvert {
			timeout, err = strconv.Atoi(route.AggregateIssuesTimeout)
		}
		if err != nil {
			log.Printf("%q settings: Can't convert 'AggregateIssuesTimeout'(%q) to seconds.",
				route.Name, route.AggregateIssuesTimeout)
		}
	}
	route.AggregateIssuesNumber = timeout
	return route
}
