package scanservice

import (
	"dbservice"
	"formatting"
	"layout"
	"log"
	"os"
	"plugins"
	"settings"
	"sync"
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
	wg sync.WaitGroup
	mu sync.Mutex
	emailCounts int
	sets *settings.Settings
}
func (plg *DemoEmailPlugin) Init() error {	return nil}
func (plg *DemoEmailPlugin) Send(data map[string]string) error {
	plg.mu.Lock()
	plg.emailCounts++
	plg.mu.Unlock()
	plg.wg.Done()
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

	demoEmailPlg.wg.Add(1)
	for _, scan := range scans {
		srv := new(ScanService)
		srv.ResultHandling(scan, plugins)
	}
	demoEmailPlg.wg.Wait()

	/*
	if demoEmailPlg.emailCounts != 0 && (n+1) != wantToAggregateIssues {
		t.Errorf("Email was sent for %dth scan. We want to aggregate %d issues.",
			n+1, wantToAggregateIssues)
	}
	if demoEmailPlg.emailCounts != 0 && (n+1) == wantToAggregateIssues {
		demoEmailPlg.emailCounts = 0
	}

	 */
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

func TestAggregateSeveralPlugins(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}

	const (
		timeoutBase = 3
	)

	dbPathReal := dbservice.DbPath
	defer func() {
		os.Remove(dbservice.DbPath)
		dbservice.DbPath = dbPathReal
	}()
	dbservice.DbPath = "test_" + dbPathReal

	setting1 :=  &settings.Settings{
		PluginName:"demoPlugin1",
	}
	setting2 :=  &settings.Settings{
		PluginName:"demoPlugin2",
		AggregateIssuesNumber: 2,
		AggregateTimeoutSeconds: timeoutBase,
	}
	setting3 :=  &settings.Settings{
		PluginName:"demoPlugin3",
		AggregateTimeoutSeconds: timeoutBase*2,
	}

	demoEmailPlg1 := DemoEmailPlugin{
		emailCounts: 0,
		sets:        setting1,
	}
	demoEmailPlg2 := DemoEmailPlugin{
		emailCounts: 0,
		sets:        setting2,
	}
	demoEmailPlg3 := DemoEmailPlugin{
		emailCounts: 0,
		sets:        setting3,
	}

	plugins := map[string]plugins.Plugin {
		"demoPlugin1": &demoEmailPlg1,
		"demoPlugin2": &demoEmailPlg2,
		"demoPlugin3": &demoEmailPlg3,
	}

	log.Println("Add First scan")
	srv1 := new(ScanService)
	srv1.ResultHandling(mockScan1, plugins)
	// after first scan only first plugin has to send a message
	if demoEmailPlg1.emailCounts != 1  {
		t.Error("The first plugin didn't send a message after first scan")
	}
	if demoEmailPlg2.emailCounts != 0  {
		t.Error("The second plugin sent a message after first scan.")
	}
	if demoEmailPlg3.emailCounts != 0  {
		t.Error("The third plugin sent a message after first scan")
	}

	// Add second scan has to trigger 1th and 2th plugins
	log.Println("Add Second scan")
	srv2 := new(ScanService)
	srv2.ResultHandling(mockScan2, plugins)
	if demoEmailPlg1.emailCounts != 2  {
		t.Error("The first plugin didn't send a message after second scan")
	}
	if demoEmailPlg2.emailCounts != 1  {
		t.Error("The second plugin didn't send a message after second scan.")
	}
	if demoEmailPlg3.emailCounts != 0  {
		t.Error("The third plugin sent a message after second scan")
	}

	log.Printf("Waiting %d second...", 1)
	time.Sleep(time.Duration(1) *time.Second)

	// Add third scan
	log.Println("Add Third scan")
	srv3 := new(ScanService)
	srv3.ResultHandling(mockScan3, plugins)
	if demoEmailPlg1.emailCounts != 3  {
		t.Error("The first plugin didn't send a message after third scan and without timeout")
	}
	if demoEmailPlg2.emailCounts != 1  {
		t.Log(demoEmailPlg2.emailCounts)
		t.Error("The second plugin sent a message after third scan and without timeout.")
	}
	if demoEmailPlg3.emailCounts != 0  {
		t.Error("The third plugin sent a message after third scan and without timeout")
	}

	log.Printf("Waiting %d second...", timeoutBase)
	time.Sleep(time.Duration(timeoutBase) *time.Second)

	if demoEmailPlg2.emailCounts != 2  {
		t.Error("The second plugin didn't send  messages after second scan and timeout.")
	}

	log.Printf("Waiting %d second again...", timeoutBase+1)
	time.Sleep(time.Duration(timeoutBase+1) *time.Second)

	if demoEmailPlg1.emailCounts != 3  {
		t.Error("The First plugin sent a wrong message.")
	}
	if demoEmailPlg2.emailCounts != 2  {
		t.Error("The Second plugin sent a wrong message.")
	}
	if demoEmailPlg3.emailCounts != 1  {
		t.Error("The third plugin didn't send a message after third scan and big timeout")
	}
}