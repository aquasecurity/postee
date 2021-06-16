package msgservice

import (
	"os"
	"sync"
	"testing"

	"github.com/aquasecurity/postee/dbservice"
	"github.com/aquasecurity/postee/routes"
)

func TestAggregateIssuesPerTicket(t *testing.T) {
	dbPathReal := dbservice.DbPath
	defer func() {
		os.Remove(dbservice.DbPath)
		dbservice.DbPath = dbPathReal
	}()
	dbservice.DbPath = "test_webhooks.db"

	demoEmailOutput := &DemoEmailOutput{
		emailCounts: 0,
	}

	scans := []string{mockScan1, mockScan2, mockScan3, mockScan4}

	srvUrl := ""
	demoRoute := &routes.InputRoute{}

	demoRoute.Name = "demo-route"
	demoRoute.Plugins.AggregateIssuesNumber = 3
	demoRoute.Plugins.PolicyShowAll = true

	demoInptEval := &DemoInptEval{}

	demoEmailOutput.wg = &sync.WaitGroup{}
	demoEmailOutput.wg.Add(1)

	for _, scan := range scans {
		srv := new(MsgService)
		srv.MsgHandling([]byte(scan), demoEmailOutput, demoRoute, demoInptEval, &srvUrl)
	}

	demoEmailOutput.wg.Wait()

	expectedSntCnt := 1
	expectedRenderCnt := 4
	expectedAggrRenderCnt := 1

	if demoEmailOutput.getEmailsCount() != expectedSntCnt {
		t.Errorf("The number of sent email doesn't match expected value. Sent: %d, expected: %d ", demoEmailOutput.getEmailsCount(), expectedSntCnt)
	}

	if demoInptEval.renderCnt != expectedRenderCnt {
		t.Errorf("The number of render procedure invocations doesn't match expected value. It's called %d times, expected: %d ", demoInptEval.renderCnt, expectedRenderCnt)
	}

	if demoInptEval.aggrCnt != expectedAggrRenderCnt {
		t.Errorf("The number of aggregation procedure invocations doesn't match expected value. It's called %d times, expected: %d ", demoInptEval.aggrCnt, expectedAggrRenderCnt)
	}
}

//TODO add negative tests when no aggregation is configured and when input evaluator doesn't support aggregation
