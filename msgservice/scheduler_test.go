package msgservice

import (
	"sync"
	"testing"

	"github.com/aquasecurity/postee/v2/outputs"
	"github.com/aquasecurity/postee/v2/routes"
)

func TestSheduler(t *testing.T) {
	routeName := "test-schedule"
	demoRoute := &routes.InputRoute{}
	demoRoute.Name = routeName

	demoRoute.Plugins.AggregateTimeoutSeconds = 3

	demoSend := func(plg outputs.Output, cnt map[string]string) {
		err := plg.Send(cnt)
		if err != nil {
			t.Fatal("error Send")
		}
	}
	demoAggregate := func(outputName string, currentContent map[string]string, counts int, ignoreLength bool) []map[string]string {
		return []map[string]string{
			{
				"title":       "title1",
				"description": "description1",
			},
			{
				"title":       "title2",
				"description": "description2",
			},
		}
	}
	demoInptEval := &DemoInptEval{}

	demoEmailOutput := &DemoEmailOutput{
		emailCounts: 0,
	}

	demoEmailOutput.wg = &sync.WaitGroup{}
	demoEmailOutput.wg.Add(1)

	RunScheduler(demoRoute, demoSend, demoAggregate, demoInptEval, &routeName, demoEmailOutput)

	demoEmailOutput.wg.Wait()
	demoRoute.StopScheduler()

}
