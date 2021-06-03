package scanservice

import (
	"log"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/aquasecurity/postee/dbservice"
	"github.com/aquasecurity/postee/formatting"
	"github.com/aquasecurity/postee/layout"
	"github.com/aquasecurity/postee/routes"
)

var (
	mockScan1 = `{"image":"Demo mock image1","registry":"registry1","vulnerability_summary":{"critical":0,"high":1,"medium":3,"low":4,"negligible":5},"image_assurance_results":{"disallowed":true}}`
	mockScan2 = `{"image":"Demo mock Image2","registry":"registry2","vulnerability_summary":{"critical":0,"high":0,"medium":3,"low":4,"negligible":5},"image_assurance_results":{"disallowed":false}}`
	mockScan3 = `{"image":"Demo mock Image3","registry":"Registry3","vulnerability_summary":{"critical":0,"high":0,"medium":0,"low":4,"negligible":5},"image_assurance_results":{"disallowed":true}}`
	mockScan4 = `{"image":"Demo mock image4","registry":"registry4","vulnerability_summary":{"critical":0,"high":0,"medium":0,"low":0,"negligible":5},"image_assurance_results":{"disallowed":true}}`
	mockScan5 = `{"image":"Demo mock image5","registry":"registry5","vulnerability_summary":{"critical":1,"high":2,"medium":3,"low":4,"negligible":5},"image_assurance_results":{"disallowed":true}}`
)

type DemoInptEval struct {
	rndMu     sync.Mutex
	aggrMu    sync.Mutex
	renderCnt int
	aggrCnt   int
}

func (inptEval *DemoInptEval) Eval(in map[string]interface{}, serverUrl string) (map[string]string, error) {
	inptEval.rndMu.Lock()
	inptEval.renderCnt++
	inptEval.rndMu.Unlock()
	return map[string]string{
		"title":       in["image"].(string),
		"description": in["image"].(string),
	}, nil
}
func (inptEval *DemoInptEval) BuildAggregatedContent(items []map[string]string) (map[string]string, error) {
	inptEval.aggrMu.Lock()
	inptEval.aggrCnt++
	inptEval.aggrMu.Unlock()

	agrTitle := []string{}
	agrDescription := []string{}
	for _, item := range items {
		agrTitle = append(agrTitle, item["title"])
		agrDescription = append(agrDescription, item["description"])
	}

	return map[string]string{
		"title":       strings.Join(agrTitle, ","),
		"description": strings.Join(agrDescription, ","),
	}, nil
}
func (inptEval *DemoInptEval) IsAggregationSupported() bool {
	return true
}

type DemoEmailOutput struct {
	wg          *sync.WaitGroup
	mu          sync.Mutex
	emailCounts int
}

func (plg *DemoEmailOutput) getEmailsCount() int {
	plg.mu.Lock()
	e := plg.emailCounts
	plg.mu.Unlock()
	return e
}

func (plg *DemoEmailOutput) Init() error { return nil }
func (plg *DemoEmailOutput) Send(data map[string]string) error {
	log.Printf("Sending through demo plugin..\n")
	log.Printf("%s\n", data["title"])

	plg.mu.Lock()
	plg.emailCounts++
	plg.mu.Unlock()
	if plg.wg != nil {
		plg.wg.Done()
	}
	return nil
}

func (plg *DemoEmailOutput) Terminate() error { return nil }
func (plg *DemoEmailOutput) GetLayoutProvider() layout.LayoutProvider {
	return new(formatting.HtmlProvider)
}

func TestAggregateIssuesPerTicket(t *testing.T) {
	dbPathReal := dbservice.DbPath
	defer func() {
		os.Remove(dbservice.DbPath)
		dbservice.DbPath = dbPathReal
	}()
	dbservice.DbPath = "test_webhooks.db"

	demoEmailOutput := &DemoEmailOutput{
		emailCounts: 0,
	}

	scans := []string{mockScan1, mockScan2, mockScan3, mockScan4}

	srvUrl := ""
	demoRoute := &routes.InputRoute{}

	demoRoute.Name = "demo-route"
	demoRoute.Plugins.AggregateIssuesNumber = 3
	demoRoute.Plugins.PolicyShowAll = true

	demoInptEval := &DemoInptEval{}

	demoEmailOutput.wg = &sync.WaitGroup{}
	demoEmailOutput.wg.Add(1)

	for _, scan := range scans {
		srv := new(ScanService)
		srv.ResultHandling([]byte(scan), demoEmailOutput, demoRoute, demoInptEval, &srvUrl)
	}

	demoEmailOutput.wg.Wait()

	expectedSntCnt := 1
	expectedRenderCnt := 4
	expectedAggrRenderCnt := 1

	if demoEmailOutput.getEmailsCount() != expectedSntCnt {
		t.Errorf("The number of sent email doesn't match expected value. Sent: %d, expected: %d ", demoEmailOutput.getEmailsCount(), expectedSntCnt)
	}

	if demoInptEval.renderCnt != expectedRenderCnt {
		t.Errorf("The number of render procedure invocations doesn't match expected value. It's called %d times, expected: %d ", demoInptEval.renderCnt, expectedRenderCnt)
	}

	if demoInptEval.aggrCnt != expectedAggrRenderCnt {
		t.Errorf("The number of aggregation procedure invocations doesn't match expected value. It's called %d times, expected: %d ", demoInptEval.aggrCnt, expectedAggrRenderCnt)
	}
}

//TODO add negative tests when no aggregation is configured and when input evaluator doesn't support aggregation
