package routes

import (
	"log"
	"time"

	"github.com/aquasecurity/postee/plugins"
)

func (route *InputRoutes) IsSchedulerRun() bool {
	return route.scheduling != nil
}

var getTicker = func(seconds int) *time.Ticker {
	return time.NewTicker(time.Duration(seconds) * time.Second)
}

func (route *InputRoutes) RunScheduler(
	fnSend func(plg plugins.Plugin, name *string, cnt map[string]string),
	fnAggregate func(pluginName string, currentContent map[string]string, counts int, ignoreLength bool) []map[string]string,
) {
	log.Printf("Scheduler is activated for route %q. Period: %d sec", route.Name, route.AggregateTimeoutSeconds)

	ticker := getTicker(route.AggregateTimeoutSeconds)
	route.scheduling = make(chan struct{})

	go func(done chan struct{}, currentTicker *time.Ticker) {
		for {
			select {
			case <-done:
				currentTicker.Stop()
				log.Printf("Scheduler for %q was stopped", route.Name)
				return
			case <-currentTicker.C:
				log.Printf("Scheduler triggered for %q", route.Name)
				queue := fnAggregate(route.Name, nil, 0, false)
				if len(queue) > 0 {
					//					fnSend(plg, name, buildAggregatedContent(queue, plg.GetLayoutProvider()))
				}
			}
		}
	}(route.scheduling, ticker)
}

func (route *InputRoutes) StopScheduler() {
	if route.scheduling != nil {
		close(route.scheduling)
	}
}
