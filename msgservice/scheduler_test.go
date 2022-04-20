package msgservice

import (
	"sync"
	"testing"
	"time"

	"github.com/aquasecurity/postee/v2/actions"
	"github.com/aquasecurity/postee/v2/routes"
	"github.com/stretchr/testify/assert"
)

func TestScheduler(t *testing.T) {
	routeName := "test-schedule"
	demoRoute := &routes.InputRoute{}
	demoRoute.Name = routeName

	demoRoute.Plugins.AggregateTimeoutSeconds = 3

	demoSend := func(plg actions.Action, cnt map[string]string) {
		err := plg.Send(cnt)
		if err != nil {
			t.Fatal("error Send")
		}
	}
	tickerInvocations := 0
	demoAggregate := func(outputName string, currentContent map[string]string, counts int, ignoreLength bool) []map[string]string {
		tickerInvocations++
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

	demoEmailAction := &DemoEmailAction{
		emailCounts: 0,
	}

	demoEmailAction.wg = &sync.WaitGroup{}
	demoEmailAction.wg.Add(1)

	RunScheduler(demoRoute, demoSend, demoAggregate, demoInptEval, &routeName, demoEmailAction)

	demoEmailAction.wg.Wait()
	demoRoute.StopScheduler()

	time.Sleep(time.Duration(2*demoRoute.Plugins.AggregateTimeoutSeconds) * time.Second) //make sure ticker is not invoked anymore

	assert.Equal(t, 1, tickerInvocations)
}
