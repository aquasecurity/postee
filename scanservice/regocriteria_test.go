package scanservice

import (
	"os"
	"sync"
	"testing"

	"github.com/aquasecurity/postee/dbservice"
	"github.com/aquasecurity/postee/routes"
)

func TestRegoCriteria(t *testing.T) {
	tests := []struct {
		input        string
		caseDesc     string
		regoCriteria string
		shouldPass   bool
	}{
		{
			input:        mockScan1,
			caseDesc:     "Empty rule should allow",
			regoCriteria: "",
			shouldPass:   true,
		},
		{
			input:        mockScan1,
			caseDesc:     "Matching rule",
			regoCriteria: `contains(input.image, "image1")`,
			shouldPass:   true,
		},
		{
			input:        mockScan2,
			caseDesc:     "not matching rule",
			regoCriteria: `contains(input.image, "image1")`,
			shouldPass:   false,
		},
	}
	for _, test := range tests {
		validateRegoInput(t, test.caseDesc, test.input, test.regoCriteria, test.shouldPass)
	}

}
func validateRegoInput(t *testing.T, caseDesc string, input string, regoCriteria string, shouldPass bool) {
	dbPathReal := dbservice.DbPath
	defer func() {
		os.Remove(dbservice.DbPath)
		dbservice.DbPath = dbPathReal
	}()
	dbservice.DbPath = "test_webhooks.db"

	demoEmailOutput := &DemoEmailOutput{
		emailCounts: 0,
	}

	srvUrl := ""
	expected := 0
	if shouldPass {
		expected = 1
	}

	demoRoute := &routes.InputRoute{}

	demoRoute.Name = "demo-route"
	demoRoute.Input = regoCriteria

	demoInptEval := &DemoInptEval{}

	demoEmailOutput.wg = &sync.WaitGroup{}
	demoEmailOutput.wg.Add(expected)

	srv := new(ScanService)
	srv.ResultHandling([]byte(input), demoEmailOutput, demoRoute, demoInptEval, &srvUrl)

	demoEmailOutput.wg.Wait()

	if demoEmailOutput.getEmailsCount() != expected {
		t.Errorf("[%s] Wrong number of Send method calls: expected %d, got %d", caseDesc, expected, demoEmailOutput.getEmailsCount())
	}

}
