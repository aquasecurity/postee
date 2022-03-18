package msgservice

import (
	"os"
	"sync"
	"testing"

	"github.com/aquasecurity/postee/v2/dbservice"
	"github.com/aquasecurity/postee/v2/routes"
)

func TestAggregateIssuesPerTicket(t *testing.T) {
	tests := []struct {
		caseDesc              string
		expectedSntCnt        int
		expectedRenderCnt     int
		expectedAggrRenderCnt int
		skipAggrSpprt         bool
	}{
		{
			caseDesc:              "basic",
			expectedSntCnt:        1,
			expectedRenderCnt:     4,
			expectedAggrRenderCnt: 1,
		},
		{
			caseDesc:              "no aggregation supported",
			expectedSntCnt:        4,
			expectedRenderCnt:     4,
			expectedAggrRenderCnt: 0,
			skipAggrSpprt:         true,
		},
	}

	dbPathReal := dbservice.DbPath
	defer func() {
		os.Remove(dbservice.DbPath)
		dbservice.ChangeDbPath(dbPathReal)
	}()
	dbservice.ChangeDbPath("test_webhooks.db")

	for _, test := range tests {
		doAggregate(t, test.caseDesc, test.expectedSntCnt, test.expectedRenderCnt, test.expectedAggrRenderCnt, test.skipAggrSpprt)
	}

}
func doAggregate(t *testing.T, caseDesc string, expectedSntCnt int, expectedRenderCnt int, expectedAggrRenderCnt int, skipAggrSpprt bool) {
	demoEmailOutput := &DemoEmailOutput{
		emailCounts: 0,
	}

	scans := []string{mockScan1, mockScan2, mockScan3, mockScan4}

	srvUrl := ""
	demoRoute := &routes.InputRoute{}

	demoRoute.Name = "demo-route"
	demoRoute.Plugins.AggregateMessageNumber = 3

	demoInptEval := &DemoInptEval{
		skipAggrSpprt: skipAggrSpprt,
	}

	demoEmailOutput.wg = &sync.WaitGroup{}
	demoEmailOutput.wg.Add(expectedSntCnt)

	for _, scan := range scans {
		srv := new(MsgService)
		srv.MsgHandling([]byte(scan), demoEmailOutput, demoRoute, demoInptEval, &srvUrl)
	}

	demoEmailOutput.wg.Wait()

	if demoEmailOutput.getEmailsCount() != expectedSntCnt {
		t.Errorf("%s: The number of sent email doesn't match expected value. Sent: %d, expected: %d ", caseDesc, demoEmailOutput.getEmailsCount(), expectedSntCnt)
	}

	if demoInptEval.renderCnt != expectedRenderCnt {
		t.Errorf("%s: The number of render procedure invocations doesn't match expected value. It's called %d times, expected: %d ", caseDesc, demoInptEval.renderCnt, expectedRenderCnt)
	}

	if demoInptEval.aggrCnt != expectedAggrRenderCnt {
		t.Errorf("%s: The number of aggregation procedure invocations doesn't match expected value. It's called %d times, expected: %d ", caseDesc, demoInptEval.aggrCnt, expectedAggrRenderCnt)
	}
}
