package routes

import (
	"log"
	"time"

	"github.com/aquasecurity/postee/data"
	"github.com/aquasecurity/postee/outputs"
)

func (route *InputRoute) IsSchedulerRun() bool {
	return route.scheduling != nil
}

var getTicker = func(seconds int) *time.Ticker {
	return time.NewTicker(time.Duration(seconds) * time.Second)
}
var RunScheduler = func(
	route *InputRoute,
	fnSend func(plg outputs.Output, name *string, cnt map[string]string),
	fnAggregate func(outputName string, currentContent map[string]string, counts int, ignoreLength bool) []map[string]string,
	inpteval data.Inpteval,
	name *string,
	output outputs.Output,
) {
	log.Printf("Scheduler is activated for route %q. Period: %d sec", route.Name, route.Plugins.AggregateTimeoutSeconds)

	ticker := getTicker(route.Plugins.AggregateTimeoutSeconds)
	route.StartScheduler()

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
					aggregated, err := inpteval.BuildAggregatedContent(queue)
					if err != nil {
						log.Printf("Unable to build aggregated contents %v\n", err)
					}
					fnSend(output, &route.Name, aggregated)
				}
			}
		}
	}(route.scheduling, ticker)
}

func (route *InputRoute) StartScheduler() { //TODO scheduler should be stopped somewhere
	route.scheduling = make(chan struct{})
}

func (route *InputRoute) StopScheduler() { //TODO scheduler should be stopped somewhere
	if route.scheduling != nil {
		close(route.scheduling)
	}
}
