package scanservice

import (
	"dbservice"
	"formatting"
	"layout"
	"os"
	"plugins"
	"settings"
	"testing"
	"time"
)
var (
	mockScan1 = `{"image":"Demo mock image1","registry":"registry1","vulnerability_summary":{"critical":0,"high":1,"medium":3,"low":4,"negligible":5},"image_assurance_results":{"disallowed":true}}`
	mockScan2 = `{"image":"Demo mock Image2","registry":"registry2","vulnerability_summary":{"critical":0,"high":0,"medium":3,"low":4,"negligible":5},"image_assurance_results":{"disallowed":false}}`
	mockScan3 = `{"image":"Demo mock Image3","registry":"Registry3","vulnerability_summary":{"critical":0,"high":0,"medium":0,"low":4,"negligible":5},"image_assurance_results":{"disallowed":true}}`
	mockScan4 = `{"image":"Demo mock image4","registry":"registry4","vulnerability_summary":{"critical":0,"high":0,"medium":0,"low":0,"negligible":5},"image_assurance_results":{"disallowed":true}}`
	mockScan5 = `{"image":"Demo mock image5","registry":"registry5","vulnerability_summary":{"critical":1,"high":2,"medium":3,"low":4,"negligible":5},"image_assurance_results":{"disallowed":true}}`
)

type DemoEmailPlugin struct {
	emailCounts int
	sets *settings.Settings
}
func (plg *DemoEmailPlugin) Init() error {	return nil}
func (plg *DemoEmailPlugin) Send(data map[string]string) error {
	plg.emailCounts++
	return nil
}

func (plg *DemoEmailPlugin) Terminate() error { return nil}
func (plg *DemoEmailPlugin) GetLayoutProvider() layout.LayoutProvider {
	return new(formatting.HtmlProvider)
}
func (plg *DemoEmailPlugin) GetSettings() *settings.Settings {
	return plg.sets
}

func TestAggregateIssuesPerTicket(t *testing.T) {
	dbPathReal := dbservice.DbPath
	defer func() {
		os.Remove(dbservice.DbPath)
		dbservice.DbPath = dbPathReal
	}()
	dbservice.DbPath = "test_" + dbPathReal

	const wantToAggregateIssues = 3

	setting1 :=  &settings.Settings{
		IgnoreImageName:       nil,
		AggregateIssuesNumber: wantToAggregateIssues,
	}

	demoEmailPlg := DemoEmailPlugin{
		emailCounts: 0,
		sets:        setting1,
	}

	plugins := map[string]plugins.Plugin {
		"email": &demoEmailPlg,
	}

	scans := []string{mockScan1, mockScan2, mockScan3, mockScan4}

	for n, scan := range scans {
		srv := new(ScanService)
		srv.ResultHandling(scan, plugins)
		if demoEmailPlg.emailCounts != 0 && (n+1) != wantToAggregateIssues {
			t.Errorf("Email was sent for %dth scan. We want to aggregate %d issues.",
				n+1, wantToAggregateIssues)
		}
		if demoEmailPlg.emailCounts != 0 && (n+1) == wantToAggregateIssues {
			demoEmailPlg.emailCounts = 0
		}
	}
}

func TestAggregateTimeoutSeconds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}

	const SleepingSec = 2

	dbPathReal := dbservice.DbPath
	defer func() {
		os.Remove(dbservice.DbPath)
		dbservice.DbPath = dbPathReal
	}()
	dbservice.DbPath = "test_" + dbPathReal

	setting1 :=  &settings.Settings{
		IgnoreImageName:        nil,
		AggregateTimeoutSeconds: SleepingSec,
	}

	demoEmailPlg := DemoEmailPlugin{
		emailCounts: 0,
		sets:        setting1,
	}

	plugins := map[string]plugins.Plugin {
		"email": &demoEmailPlg,
	}

	srv := new(ScanService)
	srv.ResultHandling(mockScan1, plugins)
	if demoEmailPlg.emailCounts != 0 {
		t.Errorf("The first scan was added. ScanService had to wait %d sec before sending", SleepingSec)
	}
	srv.ResultHandling(mockScan2, plugins)
	if demoEmailPlg.emailCounts != 0 {
		t.Errorf("The second scan was added. ScanService had to wait %d sec before sending", SleepingSec)
	}

	t.Logf("Test will be waiting %d seconds...", SleepingSec+1)
	time.Sleep(time.Duration(SleepingSec+1) *time.Second)
	if demoEmailPlg.emailCounts != 1 {
		t.Error("ScanService didn't send a package")
	} else {
		t.Log("ScanService sent a package successful!")
	}
}