package msgservice

import (
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/aquasecurity/postee/v2/dbservice"
	"github.com/aquasecurity/postee/v2/dbservice/boltdb"
	"github.com/aquasecurity/postee/v2/routes"
)

var (
	scnWithOwners = map[string]interface{}{
		"image":                    "Demo mock image1",
		"registry":                 "registry1",
		"vulnerability_summary":    map[string]int{"critical": 0, "high": 1, "medium": 3, "low": 4, "negligible": 5},
		"image_assurance_results":  map[string]interface{}{"disallowed": true},
		"application_scope_owners": []string{"recipient1@aquasec.com", "recipient1@aquasec.com"},
	}
)

func TestApplicationScopeOwner(t *testing.T) {
	db = boltdb.NewBoltDb()
	oldDb := dbservice.Db
	dbservice.Db = db
	dbPathReal := db.DbPath
	defer func() {
		os.Remove(db.DbPath)
		db.DbPath = dbPathReal
		dbservice.Db = oldDb
	}()
	db.DbPath = "test_webhooks.db"

	demoEmailOutput := &DemoEmailOutput{
		emailCounts: 0,
	}

	srvUrl := ""
	demoRoute := &routes.InputRoute{}

	demoRoute.Name = "demo-route"

	demoInptEval := &DemoInptEval{}

	demoEmailOutput.wg = &sync.WaitGroup{}
	demoEmailOutput.wg.Add(1)

	srv := new(MsgService)
	if srv.EvaluateRegoRule(demoRoute, []byte(scnWithOwners)) {
		srv.MsgHandling([]byte(scnWithOwners), demoEmailOutput, demoRoute, demoInptEval, &srvUrl)
	}

	demoEmailOutput.wg.Wait()

	if len(demoEmailOutput.payloads) != 1 {
		t.Errorf("Output Send method isn't called as expected! Number of invocation expected %d, got: %d", 1, len(demoEmailOutput.payloads))
	}
	sent := demoEmailOutput.payloads[0]

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
