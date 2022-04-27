package msgservice

import (
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/aquasecurity/postee/v2/dbservice"
	"github.com/aquasecurity/postee/v2/routes"
)

var (
	scnWithOwners = `{
		"image":"Demo mock image1",
		"registry":"registry1",
		"vulnerability_summary":{"critical":0,"high":1,"medium":3,"low":4,"negligible":5},
		"image_assurance_results":{"disallowed":true},
		"application_scope_owners": ["recipient1@aquasec.com", "recipient1@aquasec.com"]
	}`
)

func TestApplicationScopeOwner(t *testing.T) {
	dbPathReal := dbservice.DbPath
	defer func() {
		os.Remove(dbservice.DbPath)
		dbservice.ChangeDbPath(dbPathReal)
	}()
	dbservice.ChangeDbPath("test_webhooks.db")

	demoEmailAction := &DemoEmailAction{
		emailCounts: 0,
	}

	srvUrl := ""
	demoRoute := &routes.InputRoute{}

	demoRoute.Name = "demo-route"

	demoInptEval := &DemoInptEval{}

	demoEmailAction.wg = &sync.WaitGroup{}
	demoEmailAction.wg.Add(1)

	srv := new(MsgService)
	if srv.EvaluateRegoRule(demoRoute, []byte(scnWithOwners)) {
		srv.MsgHandling([]byte(scnWithOwners), demoEmailAction, demoRoute, demoInptEval, &srvUrl)
	}

	demoEmailAction.wg.Wait()

	if len(demoEmailAction.payloads) != 1 {
		t.Errorf("Action Send method isn't called as expected! Number of invocation expected %d, got: %d", 1, len(demoEmailAction.payloads))
	}
	sent := demoEmailAction.payloads[0]

	ownersStr, ok := sent["owners"]
	if !ok {
		t.Errorf("Owners key is missed from output payload")
	}
	owners := strings.Split(ownersStr, ";")
	for _, own := range owners {
		if own != "recipient1@aquasec.com" && own != "recipient2@aquasec.com" {
			t.Errorf("Unexpected owner value: '%s'", own)
		}
	}
}
