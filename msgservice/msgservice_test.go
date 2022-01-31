package msgservice

import (
	"errors"
	"os"
	"testing"

	"github.com/aquasecurity/postee/dbservice"
	"github.com/aquasecurity/postee/dbservice/boltdb"
	"github.com/aquasecurity/postee/routes"
)

var (
	db = boltdb.NewBoltDb()
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
	dbPathReal := db.DbPath
	defer func() {
		os.Remove(db.DbPath)
		db.DbPath = dbPathReal
	}()
	db.DbPath = "test_webhooks.db"

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
	if srv.EvaluateRegoRule(demoRoute, mockScan1) {
		srv.MsgHandling(mockScan1, demoEmailOutput, demoRoute, demoInptEval, &srvUrl)
	}

	if demoEmailOutput.getEmailsCount() > 0 {
		t.Errorf("Output shouldn't be called when evaluation is failed")
	}
}

func TestAggrEvalError(t *testing.T) {
	oldDb := dbservice.Db
	dbservice.Db = db
	defer func() { dbservice.Db = oldDb }()
	dbPathReal := db.DbPath
	defer func() {
		os.Remove(db.DbPath)
		db.DbPath = dbPathReal
	}()
	db.DbPath = "test_webhooks.db"

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
		if srv.EvaluateRegoRule(demoRoute, mockScan1) {
			srv.MsgHandling(mockScan1, demoEmailOutput, demoRoute, demoInptEval, &srvUrl)
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
	if srv.EvaluateRegoRule(demoRoute, map[string]interface{}{}) {
		srv.MsgHandling(map[string]interface{}{}, nil, demoRoute, demoInptEval, &srvUrl)
	}

	if demoInptEval.renderCnt != 0 {
		t.Errorf("Eval() shouldn't be called if no output is passed to ResultHandling()")
	}
}
