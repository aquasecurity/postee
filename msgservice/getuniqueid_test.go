package msgservice

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/aquasecurity/postee/v2/dbservice"
	"github.com/aquasecurity/postee/v2/routes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		if srv.EvaluateRegoRule(demoRoute, []byte(inp)) {
			srv.MsgHandling([]byte(inp), demoEmailOutput, demoRoute, demoInptEval, &srvUrl)
		}
	}

	demoEmailOutput.wg.Wait()

	if demoEmailOutput.getEmailsCount() != expected {
		t.Errorf("[%s] Wrong number of Send method calls: expected %d, got %d", caseDesc, expected, demoEmailOutput.getEmailsCount())
	}

}

func TestGetMessageUniqueId(t *testing.T) {
	tests := []struct {
		props    []string
		name     string
		context  map[string]interface{}
		filename string
		wantKey  string
		wantErr  string
	}{
		{
			props:   []string{"name"},
			name:    "Single property",
			context: map[string]interface{}{"name": "alpine"},
			wantKey: "alpine",
		},
		{
			props:   []string{"name", "registry"},
			name:    "Multi property",
			context: map[string]interface{}{"name": "alpine", "registry": "registry2"},
			wantKey: "alpine-registry2",
		},
		{
			props:   []string{"name", "cnt"},
			name:    "Numeric",
			context: map[string]interface{}{"name": "alpine", "cnt": 0},
			wantKey: "alpine-0",
		},
		{
			props:   []string{"name", "registry"},
			name:    "Missed property",
			context: map[string]interface{}{"name": "alpine"},
			wantKey: "alpine",
		},
		{
			props:   []string{"name", "meta.category"},
			name:    "Multi Level Property",
			context: map[string]interface{}{"name": "alpine", "meta": map[string]interface{}{"category": "design"}},
			wantKey: "alpine-design",
		},
		{
			props:   []string{"name", "items.id"},
			name:    "Multi Level Property With Collection",
			context: map[string]interface{}{"name": "alpine", "items": []map[string]interface{}{{"id": "KLM"}, {"id": "DEF"}}},
			wantKey: "alpine-KLM",
		},
		{
			props:   []string{"name", "items.id"},
			name:    "Multi Level Property With Empty Collection",
			context: map[string]interface{}{"name": "alpine", "items": []map[string]interface{}{}},
			wantKey: "alpine",
		},
		{
			props:   []string{"name.id"},
			name:    "Multi Level Property Referencing String",
			context: map[string]interface{}{"name": "alpine"},
		},
		{
			props:    []string{"digest", "image", "registry", "vulnerability_summary.critical", "vulnerability_summary.high", "vulnerability_summary.medium", "vulnerability_summary.low"},
			name:     "Legacy scan logic from Postee 1.0",
			filename: "all-in-one-image.json",
			wantKey:  "sha256:45388de11cfbf5c5d9e2e1418dfeac221c57cfffa1e2fffa833ac283ed029ecf-all-in-one:3.5.19223-Aqua-0-7-30-6",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var msg map[string]interface{}
			if test.filename != "" {
				fname := filepath.Join("testdata", test.filename)
				b, err := os.ReadFile(fname)
				require.NoError(t, err)
				err = json.Unmarshal(b, &msg)
				require.NoError(t, err)
			} else {
				msg = test.context
			}
			key := GetMessageUniqueId(msg, test.props)
			assert.Equal(t, test.wantKey, key)
		})
	}

}
