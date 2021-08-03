package msgservice

import (
	"os"
	"sync"
	"testing"

	"github.com/aquasecurity/postee/dbservice"
	"github.com/aquasecurity/postee/routes"
)

var (
	unique_scan1 = `{
	"image":"Demo mock image1",
	"registry":"registry1",
	"digest":"abc",
	"vulnerability_summary":{"critical":0,"high":1,"medium":3,"low":4,"negligible":5},
	"image_assurance_results":{"disallowed":true}
}`
	unique_scan2 = `{
	"image":"Demo mock image2",
	"registry":"registry2",
	"digest":"def",
	"vulnerability_summary":{"critical":0,"high":1,"medium":3,"low":4,"negligible":5},
	"image_assurance_results":{"disallowed":true}
}`
	non_unique_payload = `{
		"action": "some",
		"adjective": "nice",
		"category" : "",
		"date": 123,
		"id": 8,
		"result": 200,
		"source_ip": "192.168.0.1",
		"time": 45,
		"type": "one", 
		"user": "admin",
		"version": "2.0.1"
		
}`
)

func TestScanUniqueId(t *testing.T) {
	tests := []struct {
		inputs             []string
		caseDesc           string
		uniqueMessageProps []string
		expctdInvc         int
	}{
		{
			inputs:             []string{unique_scan1, unique_scan1},
			caseDesc:           "Same scan twice with unique message props specified",
			uniqueMessageProps: []string{"digest", "image", "registry"},
			expctdInvc:         1,
		},
		{
			inputs:     []string{unique_scan1, unique_scan1},
			caseDesc:   "Same scan twice without unique message props specified",
			expctdInvc: 2,
		},
		{
			inputs:             []string{unique_scan1, unique_scan2},
			caseDesc:           "2 unique scan with unique message props specified",
			uniqueMessageProps: []string{"digest", "image", "registry"},
			expctdInvc:         2,
		},
		{
			inputs:             []string{unique_scan1, unique_scan2},
			caseDesc:           "2 unique scan without unique message props specified",
			uniqueMessageProps: []string{"digest", "image", "registry"},
			expctdInvc:         2,
		},
		{
			inputs:     []string{non_unique_payload, non_unique_payload},
			caseDesc:   "2 non-scan inputs without unique message props specified",
			expctdInvc: 2,
		},
	}

	for _, test := range tests {
		sendInputs(t, test.caseDesc, test.inputs, test.uniqueMessageProps, test.expctdInvc)
	}

}

func sendInputs(t *testing.T, caseDesc string, inputs []string, uniqueMessageProps []string, expected int) {
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
	demoRoute := &routes.InputRoute{}

	demoRoute.Name = "demo-route"
	demoRoute.Plugins.UniqueMessageProps = uniqueMessageProps

	demoInptEval := &DemoInptEval{}

	demoEmailOutput.wg = &sync.WaitGroup{}
	demoEmailOutput.wg.Add(expected)

	for _, inp := range inputs {
		srv := new(MsgService)
		srv.MsgHandling([]byte(inp), demoEmailOutput, demoRoute, demoInptEval, &srvUrl)
	}

	demoEmailOutput.wg.Wait()

	if demoEmailOutput.getEmailsCount() != expected {
		t.Errorf("[%s] Wrong number of Send method calls: expected %d, got %d", caseDesc, expected, demoEmailOutput.getEmailsCount())
	}

}
