package msgservice

import (
	"log"
	"os"
	"testing"

	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/dbservice"
	"github.com/aquasecurity/postee/v2/dbservice/boltdb"
	"github.com/aquasecurity/postee/v2/outputs"
	"github.com/aquasecurity/postee/v2/routes"
)

func TestAggregateByTimeout(t *testing.T) {
	testDB, _ := boltdb.NewBoltDb("test_webhooks.db")
	oldDb := dbservice.Db
	dbservice.Db = testDB

	const aggregationSeconds = 3

	savedRunScheduler := RunScheduler
	schedulerInvctCnt := 0

	defer func() {
		dbservice.Db.Close()
		dbservice.Db = oldDb
		os.Remove(testDB.DbPath)
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

	testDB.DbPath = "test_webhooks.db"

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
	srv1.MsgHandling(mockScan1, demoEmailPlg, demoRoute, demoInptEval, &srvUrl)
	srv1.MsgHandling(mockScan2, demoEmailPlg, demoRoute, demoInptEval, &srvUrl)
	srv1.MsgHandling(mockScan3, demoEmailPlg, demoRoute, demoInptEval, &srvUrl)

	expectedSchedulerInvctCnt := 1

	if schedulerInvctCnt != expectedSchedulerInvctCnt {
		t.Errorf("Unexpected plugin invocation count %d, expected %d \n", schedulerInvctCnt, expectedSchedulerInvctCnt)
	}

	demoRoute.StopScheduler()
}
