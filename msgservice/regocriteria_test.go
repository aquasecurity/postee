package msgservice

import (
	"os"
	"sync"
	"testing"

	"github.com/aquasecurity/postee/dbservice"
	"github.com/aquasecurity/postee/dbservice/boltdb"
	"github.com/aquasecurity/postee/routes"
)

var (
	badRego = `
	default input = false
	
	hello {
		m := input.message
		m == "world"
	}	
`
	correctRego = `
	package postee

	default allow = false
	
	allow {
		contains(input.image, "image1")
	}
`
)

func TestRegoCriteria(t *testing.T) {
	tests := []struct {
		input        map[string]interface{}
		caseDesc     string
		regoCriteria string
		regoFilePath string
		shouldPass   bool
	}{
		{
			input:        mockScan1,
			caseDesc:     "Empty rule and files should allow",
			regoCriteria: "",
			regoFilePath: "",
			shouldPass:   true,
		},
		{
			input:        mockScan1,
			caseDesc:     "Matching rule",
			regoCriteria: `contains(input.image, "image1")`,
			regoFilePath: "",
			shouldPass:   true,
		},
		{
			input:        mockScan2,
			caseDesc:     "Not matching rule",
			regoCriteria: `contains(input.image, "image1")`,
			regoFilePath: "",
			shouldPass:   false,
		},
		{
			input:        mockScan1,
			caseDesc:     "Invalid rule",
			regoCriteria: badRego,
			regoFilePath: "",
			shouldPass:   false,
		},
		{
			input:        mockScan1,
			caseDesc:     "Matching file rule",
			regoCriteria: correctRego,
			regoFilePath: "../regoFile.rego",
			shouldPass:   true,
		},
		{
			input:        mockScan2,
			caseDesc:     "Not matching file rule",
			regoCriteria: correctRego,
			regoFilePath: "../regoFile.rego",
			shouldPass:   false,
		},
		{
			input:        mockScan1,
			caseDesc:     "Invalid file rule",
			regoCriteria: badRego,
			regoFilePath: "../regoFile.rego",
			shouldPass:   false,
		},
	}
	for _, test := range tests {
		validateRegoInput(t, test.caseDesc, test.input, test.regoCriteria, test.regoFilePath, test.shouldPass)
	}

}
func validateRegoInput(t *testing.T, caseDesc string, input map[string]interface{}, regoCriteria string, regoFilePath string, shouldPass bool) {
	db := boltdb.NewBoltDb()
	oldDb := dbservice.Db
	dbservice.Db = db
	defer func() { dbservice.Db = oldDb }()

	regoFile, err := os.Create("regoFile.rego")
	if err != nil {
		t.Error("Can't create regoFile.rego file")
	}
	regoFile.WriteString(regoCriteria)
	defer os.Remove("regoFile.rego")
	defer regoFile.Close()

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
	expected := 0
	if shouldPass {
		expected = 1
	}

	demoRoute := &routes.InputRoute{}

	demoRoute.Name = "demo-route"
	demoRoute.Input = regoCriteria
	demoRoute.InputFiles = []string{regoFilePath}

	demoInptEval := &DemoInptEval{}

	demoEmailOutput.wg = &sync.WaitGroup{}
	demoEmailOutput.wg.Add(expected)

	srv := new(MsgService)
	srv.MsgHandling(input, demoEmailOutput, demoRoute, demoInptEval, &srvUrl)

	demoEmailOutput.wg.Wait()

	if demoEmailOutput.getEmailsCount() != expected {
		t.Errorf("[%s] Wrong number of Send method calls: expected %d, got %d", caseDesc, expected, demoEmailOutput.getEmailsCount())
	}

}
