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
	mockScan1 = `{"image":"Demo mock image1"}`
	mockScan2 = `{"image":"Demo mock image2"}`
	mockScan3 = `{"image":"Demo mock image3"}`
	mockScan4 = `{"image":"Demo mock image4"}`
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

	setting1 :=  &settings.Settings{
		IgnoreImageName:        nil,
		AggregateIssuesPerTicket: 3,
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
	t.Logf("Counts of sent email: %d",demoEmailPlg.emailCounts)
	srv.ResultHandling(mockScan2, plugins)
	t.Logf("Counts of sent email: %d",demoEmailPlg.emailCounts)
	srv.ResultHandling(mockScan3, plugins)
	t.Logf("Counts of sent email: %d",demoEmailPlg.emailCounts)
	srv.ResultHandling(mockScan4, plugins)
	t.Logf("Counts of sent email: %d",demoEmailPlg.emailCounts)
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