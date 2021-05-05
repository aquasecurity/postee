package alertmgr

import (
	"github.com/aquasecurity/postee/dbservice"
	"github.com/aquasecurity/postee/plugins"
	"github.com/aquasecurity/postee/scanservice"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

func TestLoads(t *testing.T) {
	cfgData := `
Name: tenant
AquaServer: https://demolab.aquasec.com
Max_DB_Size: 13 # Max size of DB. MB. if empty then unlimited
Delete_Old_Data: 7 # delete data older than N day(s).  If empty then we do not delete.

routes:
- name: route1      #  name must be unique
  input: |
    contains(input.image, "alpine")
    input.vulnerability_summary.critical >= 3

  outputs: ["my-slack"]        #  a list of integrations which will receive a scan or an audit event
  template: raw       #  a template for this route
  Policy-Show-All: true

- name: route2      #  name must be unique
  input: |
    contains(input.image, "alpine")

  outputs: ["my-slack"]        #  a list of integrations which will receive a scan or an audit event
  template: raw       #  a template for this route
  Policy-Show-All: true

templates:
- name: raw
  body: input

outputs:

- name: splunk
  type: splunk
  enable: false
  url: http://localhost:8088
  token: 00aac750-a69c-4ebb-8771-41905f7369dd
  SizeLimit: 1000

- name: jira
  type: jira
  enable: false
  url: "https://afdesk.atlassian.net/"
  user: $JIRAUSER
  password: $JIRAPASS
  tls_verify: false
  project_key: kcv

`
	cfgName := "cfg_test.yaml"
	ioutil.WriteFile(cfgName, []byte(cfgData), 0644)
	dbPathReal := dbservice.DbPath
	savedBaseForTicker := baseForTicker
	defer func() {
		baseForTicker = savedBaseForTicker
		os.Remove(cfgName)
		os.Remove(dbservice.DbPath)
		dbservice.ChangeDbPath(dbPathReal)
	}()
	dbservice.DbPath = "test_webhooks.db"
	baseForTicker = time.Microsecond

	demoCtx := Instance()
	demoCtx.Start(cfgName)

	demoCtx.Terminate()

	/*
		pluginsNumber := 10
		if len(demoCtx.plugins) != pluginsNumber {
			t.Errorf("There are stopped plugins\nWaited: %d\nResult: %d", pluginsNumber, len(demoCtx.plugins))
		}

		_, ok := demoCtx.plugins["ms-team"]
		if !ok {
			t.Errorf("'ms-team' plugin didn't start!")
		}

		/*
				aquaWaiting := "https://demolab.aquasec.com/#/images/"
			if aquaServer != aquaWaiting {
				t.Errorf("Wrong init of AquaServer link.\nWait: %q\nGot: %q", aquaWaiting, aquaServer)
			}

	*/
	/*
		if _, ok := demoCtx.plugins["my-servicenow"]; !ok {
			t.Errorf("Plugin 'my-servicenow' didn't run!")
		}
		demoCtx.ReloadConfig()
		if len(demoCtx.plugins) != pluginsNumber {
			t.Errorf("There are stopped plugins after ReloadConfig\nWaited: %d\nResult: %d", pluginsNumber, len(demoCtx.plugins))
		}
		demoCtx.Terminate()
		time.Sleep(200 * time.Millisecond)
	*/
}

func TestServiceGetters(t *testing.T) {
	scanner := getScanService()
	if _, ok := scanner.(*scanservice.ScanService); !ok {
		t.Error("getScanService() doesn't return an instance of scanservice.ScanService")
	}
}

type demoService struct {
	buff chan string
}

func (demo *demoService) ResultHandling(input string, plugins map[string]plugins.Plugin) {
	demo.buff <- input
}
func getDemoService() *demoService {
	return &demoService{
		buff: make(chan string),
	}
}

/*
func TestSendingMessages(t *testing.T) {
	const (
		testData = "test data"
	)

	getEventServiceSaved := getEventService
	getScanServiceSaved := getScanService
	defer func() {
		getEventService = getEventServiceSaved
		getScanService = getScanServiceSaved
	}()
	dmsScan := getDemoService()
	getScanService = func() service {
		return dmsScan
	}
	dmsEvents := getDemoService()
	getEventService = func() service {
		return dmsEvents
	}
	srv := &AlertMgr{
		mutexScan:  sync.Mutex{},
		mutexEvent: sync.Mutex{},
		quit:       make(chan struct{}),
		events:     make(chan string, 1000),
		queue:      make(chan string, 1000),
		plugins:    make(map[string]plugins.Plugin),
	}
	go srv.listen()
	srv.Send(testData)
	if s := <-dmsScan.buff; s != testData {
		t.Errorf("srv.Send(%q) == %q, wanted %q", testData, s, testData)
	}
	srv.Event(testData)
	if s := <-dmsEvents.buff; s != testData {
		t.Errorf("srv.Event(%q) == %q, wanted %q", testData, s, testData)
	}
}

*/
