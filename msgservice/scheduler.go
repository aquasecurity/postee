package msgservice

import (
	"time"

	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/outputs"
	"github.com/aquasecurity/postee/v2/routes"
)

var getTicker = func(seconds int) *time.Ticker {
	return time.NewTicker(time.Duration(seconds) * time.Second)
}
var RunScheduler = func(
	route *routes.InputRoute,
	fnSend func(plg outputs.Output, cnt map[string]string),
	fnAggregate func(outputName string, currentContent map[string]string, counts int, ignoreLength bool) []map[string]string,
	inpteval data.Inpteval,
	name *string,
	output outputs.Output,
) {
	log.Logger.Infof("Scheduler is activated for route %q. Period: %d sec", route.Name, route.Plugins.AggregateTimeoutSeconds)

	ticker := getTicker(route.Plugins.AggregateTimeoutSeconds)
	route.StartScheduler()

	go func(done chan struct{}, currentTicker *time.Ticker) {
		for {
			select {
			case <-done:
				currentTicker.Stop()
				log.Logger.Infof("Scheduler for %q was stopped", route.Name)
				return
			case <-currentTicker.C:
				log.Logger.Infof("Scheduler triggered for %q", route.Name)
				queue := fnAggregate(route.Name, nil, 0, false)
				if len(queue) > 0 {
					aggregated, err := inpteval.BuildAggregatedContent(queue)
					if err != nil {
						log.Logger.Errorf("Unable to build aggregated contents %v", err)
					}
					fnSend(output, aggregated)
				}
			}
		}
	}(route.Scheduling, ticker) //it has to be public to be used here.
}
