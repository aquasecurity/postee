package scanservice

import (
	"log"
	"os"
	"testing"
	"time"

	"github.com/aquasecurity/postee/dbservice"
	"github.com/aquasecurity/postee/routes"
)

func TestAggregateByTimeout(t *testing.T) {
	const aggregationSeconds = 3

	dbPathReal := dbservice.DbPath
	defer func() {
		log.Print("Restoring base data")
		os.RemoveAll(dbservice.DbPath)
		dbservice.DbPath = dbPathReal
	}()

	dbservice.DbPath = "test_webhooks.db"

	demoEmailOutput := &DemoEmailOutput{
		emailCounts: 0,
	}

	srvUrl := ""
	demoRoute := &routes.InputRoute{}

	demoRoute.Name = "demo-route"
	demoRoute.Plugins.AggregateTimeoutSeconds = aggregationSeconds
	demoRoute.Plugins.PolicyShowAll = true

	demoInptEval := &DemoInptEval{}

	srv := new(ScanService)

	srv.ResultHandling([]byte(mockScan1), demoEmailOutput, demoRoute, demoInptEval, &srvUrl)

	if demoEmailOutput.getEmailsCount() != 0 {
		t.Errorf("The first scan was just added. ScanService should wait for %d sec before sending", aggregationSeconds)
	}

	srv.ResultHandling([]byte(mockScan2), demoEmailOutput, demoRoute, demoInptEval, &srvUrl)
	if demoEmailOutput.getEmailsCount() != 0 {
		t.Errorf("The second scan was just added. ScanService should wait for %d sec before sending", aggregationSeconds)
	}

	t.Logf("Test will be waiting %d seconds...", aggregationSeconds)
	time.Sleep(time.Duration(aggregationSeconds) * time.Second)

	if demoEmailOutput.getEmailsCount() != 1 {
		t.Error("ScanService didn't send a package")
	}

	demoRoute.StopScheduler()
}

func TestAggregateSeveralOutputs(t *testing.T) {
	const aggregationSeconds = 3
	const waiting = 1

	dbPathReal := dbservice.DbPath
	defer func() {
		os.Remove(dbservice.DbPath)
		dbservice.DbPath = dbPathReal
	}()
	dbservice.DbPath = "test_webhooks.db"
	wasSent := 0

	demoRoute1 := &routes.InputRoute{
		Name: "demo-route1",
		Plugins: routes.Plugins{
			PolicyShowAll: true,
		},
	}
	demoRoute2 := &routes.InputRoute{
		Name: "demo-route2",
		Plugins: routes.Plugins{
			PolicyShowAll:           true,
			AggregateTimeoutSeconds: aggregationSeconds * 2,
		},
	}
	demoRoute3 := &routes.InputRoute{
		Name: "demo-route3",
		Plugins: routes.Plugins{
			PolicyShowAll:           true,
			AggregateTimeoutSeconds: aggregationSeconds * 3,
		},
	}

	demoEmailPlg1 := &DemoEmailOutput{
		emailCounts: 0,
	}
	demoEmailPlg2 := &DemoEmailOutput{
		emailCounts: 0,
	}
	demoEmailPlg3 := &DemoEmailOutput{
		emailCounts: 0,
	}

	demoInptEval := &DemoInptEval{}

	srvUrl := ""

	log.Println("[INFO] Add First scan")
	wasSent++
	srv1 := new(ScanService)
	srv1.ResultHandling([]byte(mockScan1), demoEmailPlg1, demoRoute1, demoInptEval, &srvUrl)

	if demoEmailPlg1.getEmailsCount() != 1 {
		t.Error("First event: The first output didn't send a message after first scan")
	}
	if demoEmailPlg2.getEmailsCount() != 0 {
		t.Error("First event: The second output sent a message after first scan.")
	}
	if demoEmailPlg3.getEmailsCount() != 0 {
		t.Error("First event: The third output sent a message after first scan")
	}

	log.Println("[INFO] Add Second scan")
	wasSent++
	srv2 := new(ScanService)
	srv2.ResultHandling([]byte(mockScan2), demoEmailPlg2, demoRoute2, demoInptEval, &srvUrl)

	//first delay is less than timeout nothing should happen
	time.Sleep(waiting * time.Second)

	if demoEmailPlg1.getEmailsCount() != 1 {
		t.Error("Second event: The first output didn't send a message after second scan")
	}
	if demoEmailPlg2.getEmailsCount() != 0 {
		t.Error("Second event: The second output sent a message after second scan.")
	}
	if demoEmailPlg3.getEmailsCount() != 0 {
		t.Error("Second event: The third output sent a message after second scan")
	}

	log.Printf("[INFO] Waiting for %d seconds...", aggregationSeconds*2)

	//second delay should be long enough to send message
	time.Sleep(aggregationSeconds * time.Second * 2)
	if demoEmailPlg1.getEmailsCount() != 1 {
		t.Error("Second event: The first output didn't send a message after second scan")
	}
	if demoEmailPlg2.getEmailsCount() != 1 {
		t.Error("Second event: The second output didn't send a message after second scan.")
	}
	if demoEmailPlg3.getEmailsCount() != 0 {
		t.Error("Second event: The third output sent a message after second scan")
	}

	// Add third scan
	log.Println("[INFO] Add Third scan")
	wasSent++
	srv3 := new(ScanService)
	srv3.ResultHandling([]byte(mockScan3), demoEmailPlg3, demoRoute3, demoInptEval, &srvUrl)
	//small third delay for ???
	time.Sleep(waiting * time.Second)

	if demoEmailPlg3.getEmailsCount() != 0 {
		t.Error("The third output sent a message after third scan and without timeout")
	}

	log.Printf("[INFO] Waiting %d seconds...", aggregationSeconds)
	// delay #4 - still not ready yet (just repeat test)
	time.Sleep(aggregationSeconds * time.Second)

	if demoEmailPlg3.getEmailsCount() != 0 {
		t.Error("The third output sent a message after third scan and without timeout")
	}

	log.Printf("[INFO] Waiting %d millisecond again...", aggregationSeconds)

	// delay #5 long enough to process third event
	time.Sleep(aggregationSeconds * time.Second * 3)

	if demoEmailPlg3.getEmailsCount() != 1 {
		t.Error("The third output didn't send a message after third scan and big timeout")
	}
	demoRoute1.StopScheduler()
	demoRoute2.StopScheduler()
	demoRoute3.StopScheduler()
}
