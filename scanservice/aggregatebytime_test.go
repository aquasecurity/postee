package scanservice

import (
	"github.com/aquasecurity/postee/dbservice"
	"github.com/aquasecurity/postee/plugins"
	"github.com/aquasecurity/postee/settings"
	"log"
	"os"
	"sync"
	"testing"
	"time"
)

func TestAggregateByTimeout(t *testing.T) {
	const milliseconds = 300

	backupAggregator := AggregateScanAndGetQueue
	dbPathReal := dbservice.DbPath
	getTickerReal := getTicker
	defer func() {
		log.Print("Restoring base data")
		os.RemoveAll(dbservice.DbPath)
		AggregateScanAndGetQueue = backupAggregator
		dbservice.DbPath = dbPathReal
		getTicker = getTickerReal
	}()
	getTicker = func(ms int) *time.Ticker {
		return time.NewTicker(time.Duration(ms) * time.Millisecond)
	}
	dbservice.DbPath = "test_webhooks.db"
	AggregateScanAndGetQueue = func(pluginName string, currentContent map[string]string, counts int, ignoreLength bool) []map[string]string {
		return []map[string]string{
			{"title": "title", "description": "description", "url": "url"},
		}
	}

	setting1 := &settings.Settings{
		IgnoreImageName:         nil,
		AggregateTimeoutSeconds: milliseconds,
	}

	demoEmailPlg := DemoEmailPlugin{
		emailCounts: 0,
		sets:        setting1,
	}

	plugins := map[string]plugins.Plugin{
		"email": &demoEmailPlg,
	}

	demoEmailPlg.wg = &sync.WaitGroup{}
	demoEmailPlg.wg.Add(1)

	srv := new(ScanService)
	srv.ResultHandling(mockScan1, plugins)

	if demoEmailPlg.getEmailsCount() != 0 {
		t.Errorf("The first scan was added. ScanService had to wait %d sec before sending", milliseconds)
	}

	srv.ResultHandling(mockScan2, plugins)
	if demoEmailPlg.getEmailsCount() != 0 {
		t.Errorf("The second scan was added. ScanService had to wait %d sec before sending", milliseconds)
	}

	t.Logf("Test will be waiting %d milliseconds...", milliseconds)
	time.Sleep(time.Duration(milliseconds) * time.Millisecond)
	if demoEmailPlg.getEmailsCount() != 1 {
		t.Error("ScanService didn't send a package")
	}
	schedulersStop(plugins)
}

func TestAggregateSeveralPlugins(t *testing.T) {
	const milliseconds = 500
	const waiting = 100

	dbPathReal := dbservice.DbPath
	getTickerReal := getTicker
	backupAggregator := AggregateScanAndGetQueue
	defer func() {
		os.Remove(dbservice.DbPath)
		dbservice.DbPath = dbPathReal
		getTicker = getTickerReal
		AggregateScanAndGetQueue = backupAggregator
	}()
	getTicker = func(ms int) *time.Ticker {
		return time.NewTicker(time.Duration(ms) * time.Millisecond)
	}
	dbservice.DbPath = "test_webhooks.db"
	wasSent := 0
	AggregateScanAndGetQueue = func(pluginName string, currentContent map[string]string, counts int, ignoreLength bool) []map[string]string {
		log.Printf("[MOCK] %q: counts %d, was sent %d", pluginName, counts, wasSent)
		res := []map[string]string{
			{"title": "title", "description": "description", "url": "url"},
		}
		if counts > 0 {
			if wasSent == counts {
				res = append(res, map[string]string{"title": "title", "description": "description", "url": "url"})
			} else {
				return nil
			}
		}
		return res
	}

	setting1 := &settings.Settings{
		PluginName:    "demoPlugin1",
		PolicyShowAll: true,
	}
	setting2 := &settings.Settings{
		PluginName:              "demoPlugin2",
		PolicyShowAll:           true,
		AggregateIssuesNumber:   2,
		AggregateTimeoutSeconds: milliseconds * 2,
	}
	setting3 := &settings.Settings{
		PluginName:              "demoPlugin3",
		PolicyShowAll:           true,
		AggregateTimeoutSeconds: milliseconds * 3,
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

	plugins := map[string]plugins.Plugin{
		"demoPlugin1": &demoEmailPlg1,
		"demoPlugin2": &demoEmailPlg2,
		"demoPlugin3": &demoEmailPlg3,
	}

	log.Println("[INFO] Add First scan")
	wasSent++
	srv1 := new(ScanService)
	srv1.ResultHandling(mockScan1, plugins)
	time.Sleep(time.Duration(waiting) * time.Millisecond)

	// after first scan only first plugin has to send a message
	if demoEmailPlg1.getEmailsCount() != 1 {
		t.Error("The first plugin didn't send a message after first scan")
	}
	if demoEmailPlg2.getEmailsCount() != 0 {
		t.Error("The second plugin sent a message after first scan.")
	}
	if demoEmailPlg3.getEmailsCount() != 0 {
		t.Error("The third plugin sent a message after first scan")
	}

	// Add second scan has to trigger 1th and 2th plugins
	log.Println("[INFO] Add Second scan")
	wasSent++
	srv2 := new(ScanService)
	srv2.ResultHandling(mockScan2, plugins)
	time.Sleep(time.Duration(waiting) * time.Millisecond)

	if demoEmailPlg1.getEmailsCount() != 2 {
		t.Error("The first plugin didn't send a message after second scan")
	}
	if demoEmailPlg2.getEmailsCount() != 1 {
		t.Error("The second plugin didn't send a message after second scan.")
	}
	if demoEmailPlg3.getEmailsCount() != 0 {
		t.Error("The third plugin sent a message after second scan")
	}

	log.Printf("[INFO] Waiting %d millisecond...", milliseconds)
	time.Sleep(time.Duration(milliseconds) * time.Millisecond)

	// Add third scan
	log.Println("[INFO] Add Third scan")
	wasSent++
	srv3 := new(ScanService)
	srv3.ResultHandling(mockScan3, plugins)
	time.Sleep(time.Duration(waiting) * time.Millisecond)

	if demoEmailPlg1.getEmailsCount() != 3 {
		t.Error("The first plugin didn't send a message after third scan and without timeout")
	}
	if demoEmailPlg2.getEmailsCount() != 1 {
		t.Error("The second plugin sent a message after third scan and without timeout.")
	}
	if demoEmailPlg3.getEmailsCount() != 0 {
		t.Error("The third plugin sent a message after third scan and without timeout")
	}

	log.Printf("[INFO] Waiting %d millisecond...", milliseconds)
	time.Sleep(time.Duration(milliseconds) * time.Millisecond)

	if demoEmailPlg2.getEmailsCount() != 2 {
		t.Error("The second plugin didn't send  messages after second scan and timeout.")
	}

	log.Printf("[INFO] Waiting %d millisecond again...", milliseconds)
	time.Sleep(time.Duration(milliseconds) * time.Millisecond)

	if demoEmailPlg1.getEmailsCount() != 3 {
		t.Error("The First plugin sent a wrong message.")
	}
	if demoEmailPlg2.getEmailsCount() != 2 {
		t.Error("The Second plugin sent a wrong message.")
	}
	if demoEmailPlg3.getEmailsCount() != 1 {
		t.Error("The third plugin didn't send a message after third scan and big timeout")
	}

	schedulersStop(plugins)
}
