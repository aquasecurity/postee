package msgservice

import (
	"errors"
	"os"
	"testing"

	"github.com/aquasecurity/postee/v2/dbservice"
	"github.com/aquasecurity/postee/v2/dbservice/boltdb"
	"github.com/aquasecurity/postee/v2/routes"
)

type FailingInptEval struct {
	expectedError     error
	expectedAggrError error
}

func (inptEval *FailingInptEval) Eval(in map[string]interface{}, serverUrl string) (map[string]string, error) {
	if inptEval.expectedError != nil {
		return nil, inptEval.expectedError
	} else {
		return map[string]string{
			"title":       "some title",
			"description": "some description",
		}, nil
	}
}
func (inptEval *FailingInptEval) BuildAggregatedContent(items []map[string]string) (map[string]string, error) {

	return nil, inptEval.expectedAggrError
}
func (inptEval *FailingInptEval) IsAggregationSupported() bool {
	return inptEval.expectedAggrError != nil
}

func TestEvalError(t *testing.T) {
	testDB, _ := boltdb.NewBoltDb("test_webhooks.db")
	defer func() {
		testDB.Close()
		os.Remove(testDB.DbPath)
	}()

	demoEmailOutput := &DemoEmailOutput{
		emailCounts: 0,
	}

	srvUrl := ""

	demoRoute := &routes.InputRoute{}

	demoRoute.Name = "demo-route"
	evalError := errors.New("eval error")

	demoInptEval := &FailingInptEval{
		expectedError: evalError,
	}

	srv := new(MsgService)
	if srv.EvaluateRegoRule(demoRoute, []byte(mockScan1)) {
		srv.MsgHandling([]byte(mockScan1), demoEmailOutput, demoRoute, demoInptEval, &srvUrl)
	}

	if demoEmailOutput.getEmailsCount() > 0 {
		t.Errorf("Output shouldn't be called when evaluation is failed")
	}
}

func TestAggrEvalError(t *testing.T) {
	testDB, _ := boltdb.NewBoltDb("test_webhooks.db")
	oldDb := dbservice.Db
	dbservice.Db = testDB
	defer func() { dbservice.Db = oldDb }()
	defer func() {
		testDB.Close()
		os.Remove(testDB.DbPath)
	}()

	demoEmailOutput := &DemoEmailOutput{
		emailCounts: 0,
	}

	srvUrl := ""

	demoRoute := &routes.InputRoute{}

	demoRoute.Name = "demo-route"
	demoRoute.Plugins.AggregateMessageNumber = 2

	aggrEvalError := errors.New("aggregation eval error")

	demoInptEval := &FailingInptEval{
		expectedAggrError: aggrEvalError,
	}

	for i := 0; i < 2; i++ {
		srv := new(MsgService)
		if srv.EvaluateRegoRule(demoRoute, []byte(mockScan1)) {
			srv.MsgHandling([]byte(mockScan1), demoEmailOutput, demoRoute, demoInptEval, &srvUrl)
		}
	}

	if demoEmailOutput.getEmailsCount() > 0 {
		t.Errorf("Output shouldn't be called when evaluation is failed")
	}
}
func TestEmptyInput(t *testing.T) {
	dbPathReal := db.DbPath
	defer func() {
		os.Remove(db.DbPath)
		db.DbPath = dbPathReal
	}()
	db.DbPath = "test_webhooks.db"

	srvUrl := ""

	demoRoute := &routes.InputRoute{}

	demoRoute.Name = "demo-route"

	demoInptEval := &DemoInptEval{}

	srv := new(MsgService)
	if srv.EvaluateRegoRule(demoRoute, []byte("{}")) {
		srv.MsgHandling([]byte("{}"), nil, demoRoute, demoInptEval, &srvUrl)
	}

	if demoInptEval.renderCnt != 0 {
		t.Errorf("Eval() shouldn't be called if no output is passed to ResultHandling()")
	}
}

func TestMalformedJSON(t *testing.T) {
	var (
		srvUrl          = ""
		demoRoute       = &routes.InputRoute{Name: "demo-route"}
		demoInptEval    = &DemoInptEval{}
		demoEmailOutput = &DemoEmailOutput{}
	)

	srv := new(MsgService)
	srv.MsgHandling([]byte("{test:test}"), demoEmailOutput, demoRoute, demoInptEval, &srvUrl)

	if demoEmailOutput.getEmailsCount() > 0 {
		t.Errorf("Output shouldn't be called when evaluation is failed")
	}
}
