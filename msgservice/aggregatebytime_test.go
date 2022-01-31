package msgservice

import (
	"log"
	"os"
	"testing"

	"github.com/aquasecurity/postee/data"
	"github.com/aquasecurity/postee/dbservice"
	"github.com/aquasecurity/postee/dbservice/boltdb"
	"github.com/aquasecurity/postee/outputs"
	"github.com/aquasecurity/postee/routes"
)

func TestAggregateByTimeout(t *testing.T) {
	db = boltdb.NewBoltDb()
	oldDb := dbservice.Db
	dbservice.Db = db
	defer func() { dbservice.Db = oldDb }()

	const aggregationSeconds = 3

	dbPathReal := db.DbPath
	savedRunScheduler := RunScheduler
	schedulerInvctCnt := 0
	defer func() {
		os.Remove(db.DbPath)
		db.DbPath = dbPathReal
		RunScheduler = savedRunScheduler
	}()
	RunScheduler = func(
		route *routes.InputRoute,
		fnSend func(plg outputs.Output, cnt map[string]string),
		fnAggregate func(outputName string, currentContent map[string]string, counts int, ignoreLength bool) []map[string]string,
		inpteval data.Inpteval,
		name *string,
		output outputs.Output,
	) {
		log.Printf("Mocked Scheduler is activated for route %q. Period: %d sec", route.Name, route.Plugins.AggregateTimeoutSeconds)
		route.StartScheduler()

		schedulerInvctCnt++
	}

	db.DbPath = "test_webhooks.db"

	demoRoute := &routes.InputRoute{
		Name: "demo-route1",
		Plugins: routes.Plugins{
			AggregateTimeoutSeconds: aggregationSeconds,
		},
	}

	demoEmailPlg := &DemoEmailOutput{}

	demoInptEval := &DemoInptEval{}

	srvUrl := ""

	srv1 := new(MsgService)
	if srv1.EvaluateRegoRule(demoRoute, mockScan1) {
		srv1.MsgHandling(mockScan1, demoEmailPlg, demoRoute, demoInptEval, &srvUrl)
	}
	if srv1.EvaluateRegoRule(demoRoute, mockScan2) {
		srv1.MsgHandling(mockScan2, demoEmailPlg, demoRoute, demoInptEval, &srvUrl)
	}
	if srv1.EvaluateRegoRule(demoRoute, mockScan3) {
		srv1.MsgHandling(mockScan3, demoEmailPlg, demoRoute, demoInptEval, &srvUrl)
	}

	expectedSchedulerInvctCnt := 1

	if schedulerInvctCnt != expectedSchedulerInvctCnt {
		t.Errorf("Unexpected plugin invocation count %d, expected %d \n", schedulerInvctCnt, expectedSchedulerInvctCnt)
	}

	demoRoute.StopScheduler()
}
