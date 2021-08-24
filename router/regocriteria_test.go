package router

var (
	badRego = `
	default input = false
	
	hello {
		m := input.message
		m == "world"
	}	
`
	mockScan1 = map[string]interface{}{"image": "Demo mock image1", "registry": "registry1", "vulnerability_summary": map[string]int{"critical": 0, "high": 1, "medium": 3, "low": 4, "negligible": 5}, "image_assurance_results": map[string]interface{}{"disallowed": true}}
	mockScan2 = map[string]interface{}{"image": "Demo mock Image2", "registry": "registry2", "vulnerability_summary": map[string]int{"critical": 0, "high": 0, "medium": 3, "low": 4, "negligible": 5}, "image_assurance_results": map[string]interface{}{"disallowed": false}}
)

//TODO re-implement
/*
func TestRegoCriteria(t *testing.T) {
	tests := []struct {
		input        map[string]interface{}
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
			caseDesc:     "Not matching rule",
			regoCriteria: `contains(input.image, "image1")`,
			shouldPass:   false,
		},
		{
			input:        mockScan1,
			caseDesc:     "Invalid rule",
			regoCriteria: badRego,
			shouldPass:   false,
		},
	}
	for _, test := range tests {
		validateRegoInput(t, test.caseDesc, test.input, test.regoCriteria, test.shouldPass)
	}

}
func validateRegoInput(t *testing.T, caseDesc string, input map[string]interface{}, regoCriteria string, shouldPass bool) {
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

	srv := new(MsgService)
	srv.MsgHandling([]byte(input), demoEmailOutput, demoRoute, demoInptEval, &srvUrl)

	demoEmailOutput.wg.Wait()

	if demoEmailOutput.getEmailsCount() != expected {
		t.Errorf("[%s] Wrong number of Send method calls: expected %d, got %d", caseDesc, expected, demoEmailOutput.getEmailsCount())
	}

}
*/
