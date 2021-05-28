package scanservice

import (
	"os"
	"sync"
	"testing"

	"github.com/aquasecurity/postee/dbservice"
	"github.com/aquasecurity/postee/formatting"
	"github.com/aquasecurity/postee/layout"
)

var (
	mockScan1 = `{"image":"Demo mock image1","registry":"registry1","vulnerability_summary":{"critical":0,"high":1,"medium":3,"low":4,"negligible":5},"image_assurance_results":{"disallowed":true}}`
	mockScan2 = `{"image":"Demo mock Image2","registry":"registry2","vulnerability_summary":{"critical":0,"high":0,"medium":3,"low":4,"negligible":5},"image_assurance_results":{"disallowed":false}}`
	mockScan3 = `{"image":"Demo mock Image3","registry":"Registry3","vulnerability_summary":{"critical":0,"high":0,"medium":0,"low":4,"negligible":5},"image_assurance_results":{"disallowed":true}}`
	mockScan4 = `{"image":"Demo mock image4","registry":"registry4","vulnerability_summary":{"critical":0,"high":0,"medium":0,"low":0,"negligible":5},"image_assurance_results":{"disallowed":true}}`
	mockScan5 = `{"image":"Demo mock image5","registry":"registry5","vulnerability_summary":{"critical":1,"high":2,"medium":3,"low":4,"negligible":5},"image_assurance_results":{"disallowed":true}}`
)

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

	/*
		demoEmailPlg := DemoEmailOutput{
			emailCounts: 0,
		}

		outputs := map[string]outputs.Output{
			"email": &demoEmailPlg,
		}

		scans := []string{mockScan1, mockScan2, mockScan3, mockScan4}

		demoEmailPlg.wg = &sync.WaitGroup{}
		demoEmailPlg.wg.Add(1)
		for _, scan := range scans {
			srv := new(ScanService)
			srv.ResultHandling(scan, outputs)
		}
		demoEmailPlg.wg.Wait()

	*/
}
