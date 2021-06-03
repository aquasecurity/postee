package alertmgr

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/aquasecurity/postee/dbservice"
	"github.com/aquasecurity/postee/outputs"
	"github.com/aquasecurity/postee/scanservice"
)

var (
	cfgData string = `
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
  plugins:
   Policy-Show-All: true

- name: route2      #  name must be unique
  input: |
   contains(input.image, "alpine")

  outputs: ["my-slack"]        #  a list of integrations which will receive a scan or an audit event
  template: raw       #  a template for this route
  plugins:
   Policy-Show-All: true

templates:
- name: raw
  body: input

outputs:
- name: splunk
  type: splunk
  enable: true
  url: http://localhost:8088
  token: 00aac750-a69c-4ebb-8771-41905f7369dd
  SizeLimit: 1000

- name: jira
  type: jira
  enable: true
  url: "https://afdesk.atlassian.net/"
  user: admin
  password: admin
  tls_verify: false
  project_key: kcv`
)

type ctxWrapper struct {
	instance           *AlertMgr
	savedBaseForTicker time.Duration
	savedDBPath        string
	cfgPath            string
}

func (ctxWrapper *ctxWrapper) setup(cfg string) {
	ctxWrapper.savedDBPath = dbservice.DbPath
	ctxWrapper.savedBaseForTicker = baseForTicker
	ctxWrapper.cfgPath = "cfg_test.yaml"

	dbservice.DbPath = "test_webhooks.db"
	baseForTicker = time.Microsecond

	ioutil.WriteFile(ctxWrapper.cfgPath, []byte(cfgData), 0644)
	ctxWrapper.instance = Instance()
}

func (ctxWrapper *ctxWrapper) teardown() {
	ctxWrapper.instance.Terminate()

	baseForTicker = ctxWrapper.savedBaseForTicker
	os.Remove(ctxWrapper.cfgPath)
	os.Remove(dbservice.DbPath)
	dbservice.ChangeDbPath(ctxWrapper.savedDBPath)
}

func TestLoads(t *testing.T) {
	wrap := ctxWrapper{}
	wrap.setup(cfgData)

	defer wrap.teardown()

	demoCtx := wrap.instance
	demoCtx.Start(wrap.cfgPath)

	expectedOutputsCnt := 2
	if len(demoCtx.outputs) != expectedOutputsCnt {
		t.Errorf("There are stopped outputs\nWaited: %d\nResult: %d", expectedOutputsCnt, len(demoCtx.outputs))
	}

	_, ok := demoCtx.outputs["jira"]
	if !ok {
		t.Errorf("'jira' output didn't start!")
	}

	expectedSrvUrl := "https://demolab.aquasec.com/#/images/"
	if demoCtx.aquaServer != expectedSrvUrl {
		t.Errorf("Wrong init of AquaServer link.\nWait: %q\nGot: %q", expectedSrvUrl, demoCtx.aquaServer)
	}

	if _, ok := demoCtx.outputs["splunk"]; !ok {
		t.Errorf("Output 'splunk' didn't run!")
	}
}
func TestReload(t *testing.T) {
	extraOtptCfg := `
- name: jira2
  type: jira
  enable: true
  url: "https://afdesk.atlassian.net/"
  user: admin
  password: admin
  tls_verify: false
  project_key: kcv`

	wrap := ctxWrapper{}
	wrap.setup(cfgData)

	defer wrap.teardown()

	demoCtx := wrap.instance
	demoCtx.Start(wrap.cfgPath)

	expectedOutputsCnt := 2
	if len(demoCtx.outputs) != expectedOutputsCnt {
		t.Errorf("There are stopped outputs\nWaited: %d\nResult: %d", expectedOutputsCnt, len(demoCtx.outputs))
	}

	f, err := os.OpenFile(wrap.cfgPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Errorf("Can't open config %v\n", err)
	}
	defer f.Close()
	if _, err := f.WriteString(extraOtptCfg); err != nil {
		t.Errorf("Can't update config %v\n", err)
	}
	demoCtx.ReloadConfig()
	expectedOutputsAfterReload := 3

	if len(demoCtx.outputs) != expectedOutputsAfterReload {
		t.Errorf("There are stopped outputs\nWaited: %d\nResult: %d", expectedOutputsAfterReload, len(demoCtx.outputs))
	}

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

func (demo *demoService) ResultHandling(input string, outputs map[string]outputs.Output) {
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

	getScanServiceSaved := getScanService
	defer func() {
		getScanService = getScanServiceSaved
	}()
	dmsScan := getDemoService()
	getScanService = func() service {
		return dmsScan
	}
	srv := &AlertMgr{
		mutexScan: sync.Mutex{},
		quit:      make(chan struct{}),
		queue:     make(chan []byte, 1000),
		outputs:   make(map[string]outputs.Output),
	}
	go srv.listen()
	srv.Send([]byte(testData))
	if s := <-dmsScan.buff; s != testData {
		t.Errorf("srv.Send(%q) == %q, wanted %q", testData, s, testData)
	}
}
*/
