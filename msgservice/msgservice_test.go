package msgservice

import (
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/aquasecurity/postee/v2/dbservice"
	"github.com/aquasecurity/postee/v2/routes"
)

var (
	invalidJson = `{
	image : "My Image"
	}`
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

func TestInputs(t *testing.T) {
	tests := []struct {
		input      []byte
		caseDesc   string
		shouldPass bool
	}{
		{
			input:      nil,
			caseDesc:   "Empty input",
			shouldPass: false,
		},
		{
			input:      []byte(invalidJson),
			caseDesc:   "Invalid Json",
			shouldPass: false,
		},
	}
	for _, test := range tests {
		validateInputValue(t, test.caseDesc, test.input, test.shouldPass)
	}

}
func validateInputValue(t *testing.T, caseDesc string, input []byte, shouldPass bool) {
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
	expected := 0
	if shouldPass {
		expected = 1
	}

	demoRoute := &routes.InputRoute{}

	demoRoute.Name = "demo-route"

	demoInptEval := &DemoInptEval{}

	demoEmailAction.wg = &sync.WaitGroup{}
	demoEmailAction.wg.Add(expected)

	srv := new(MsgService)
	if srv.EvaluateRegoRule(demoRoute, input) {
		srv.MsgHandling(input, demoEmailAction, demoRoute, demoInptEval, &srvUrl)
	}

	demoEmailAction.wg.Wait()

	if demoEmailAction.getEmailsCount() != expected {
		t.Errorf("[%s] Wrong number of Send method calls: expected %d, got %d", caseDesc, expected, demoEmailAction.getEmailsCount())
	}

}
func TestEvalError(t *testing.T) {
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
	evalError := errors.New("eval error")

	demoInptEval := &FailingInptEval{
		expectedError: evalError,
	}

	srv := new(MsgService)
	if srv.EvaluateRegoRule(demoRoute, []byte(mockScan1)) {
		srv.MsgHandling([]byte(mockScan1), demoEmailAction, demoRoute, demoInptEval, &srvUrl)
	}

	if demoEmailAction.getEmailsCount() > 0 {
		t.Errorf("Action shouldn't be called when evaluation is failed")
	}
}

func TestAggrEvalError(t *testing.T) {
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
	demoRoute.Plugins.AggregateMessageNumber = 2

	aggrEvalError := errors.New("aggregation eval error")

	demoInptEval := &FailingInptEval{
		expectedAggrError: aggrEvalError,
	}

	for i := 0; i < 2; i++ {
		srv := new(MsgService)
		if srv.EvaluateRegoRule(demoRoute, []byte(mockScan1)) {
			srv.MsgHandling([]byte(mockScan1), demoEmailAction, demoRoute, demoInptEval, &srvUrl)
		}
	}

	if demoEmailAction.getEmailsCount() > 0 {
		t.Errorf("Action shouldn't be called when evaluation is failed")
	}
}
func TestEmptyInput(t *testing.T) {
	dbPathReal := dbservice.DbPath
	defer func() {
		os.Remove(dbservice.DbPath)
		dbservice.ChangeDbPath(dbPathReal)
	}()
	dbservice.ChangeDbPath("test_webhooks.db")

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
		demoEmailAction = &DemoEmailAction{}
	)

	srv := new(MsgService)
	srv.MsgHandling([]byte("{test:test}"), demoEmailAction, demoRoute, demoInptEval, &srvUrl)

	if demoEmailAction.getEmailsCount() > 0 {
		t.Errorf("Action shouldn't be called when evaluation is failed")
	}
}
