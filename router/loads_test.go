package router

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"

	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/msgservice"
	"github.com/aquasecurity/postee/v2/outputs"
	"github.com/aquasecurity/postee/v2/routes"
)

var (
	cfgData string = `
name: tenant
aqua-server: https://demolab.aquasec.com
max-db-size: 13 # Max size of DB. MB. if empty then unlimited
delete-old-data: 7 # delete data older than N day(s).  If empty then we do not delete.d

routes:
- name: route1      #  name must be unique
  input: |
   contains(input.image, "alpine")
   input.vulnerability_summary.critical >= 3

  outputs: ["my-slack"]        #  a list of integrations which will receive a scan or an audit event
  template: raw       #  a template for this route
  plugins:
   policy-show-all: true

- name: route2      #  name must be unique
  input: |
   contains(input.image, "alpine")

  outputs: ["my-slack"]        #  a list of integrations which will receive a scan or an audit event
  template: raw       #  a template for this route
  plugins:
   policy-show-all: true

templates:
- name: raw
  body: input

outputs:
- name: splunk
  type: splunk
  enable: true
  url: http://localhost:8088
  token: 00aac750-a69c-4ebb-8771-41905f7369dd
  size-limit: 1000

- name: jira
  type: jira
  enable: true
  url: "https://afdesk.atlassian.net/"
  user: admin
  password: admin
  tls-verify: false
  project-key: kcv`
)

type ctxWrapper struct {
	instance           *Router
	savedBaseForTicker time.Duration
	savedGetService    func() service
	savedDBPath        string
	cfgPath            string
	defaultRegoFolder  string
	commonRegoFolder   string
	buff               chan invctn
}

type invctn struct {
	outputCls   string
	templateCls string
	routeName   string
	found       bool
}

func (ctx *ctxWrapper) MsgHandling(input map[string]interface{}, output outputs.Output, route *routes.InputRoute, inpteval data.Inpteval, aquaServer *string) {
	i := invctn{
		fmt.Sprintf("%T", output),
		fmt.Sprintf("%T", inpteval),
		route.Name,
		false,
	}
	ctx.buff <- i
}

func (ctxWrapper *ctxWrapper) setup(cfg string) {
	ctxWrapper.init()

	ctxWrapper.cfgPath = "cfg_test.yaml"
	err := ioutil.WriteFile(ctxWrapper.cfgPath, []byte(cfg), 0644)
	if err != nil {
		log.Printf("Can't write to %s", ctxWrapper.cfgPath)
	}
}
func (ctxWrapper *ctxWrapper) init() {
	ctxWrapper.savedDBPath = "test_webhooks.db"
	ctxWrapper.savedBaseForTicker = baseForTicker
	ctxWrapper.savedGetService = getScanService
	ctxWrapper.buff = make(chan invctn)

	baseForTicker = time.Microsecond
	ctxWrapper.defaultRegoFolder = "rego-templates"
	ctxWrapper.commonRegoFolder = ctxWrapper.defaultRegoFolder + "/common"
	err := os.Mkdir(ctxWrapper.defaultRegoFolder, 0777)
	if err != nil {
		log.Printf("Can't create %s %v", ctxWrapper.defaultRegoFolder, err)
	}
	err = os.Mkdir(ctxWrapper.commonRegoFolder, 0777)
	if err != nil {
		log.Printf("Can't create %s %v", ctxWrapper.defaultRegoFolder, err)
	}

	getScanService = func() service {
		return ctxWrapper
	}

	ctxWrapper.instance = Instance()
}

func (ctxWrapper *ctxWrapper) teardown() {
	ctxWrapper.instance.Terminate()

	baseForTicker = ctxWrapper.savedBaseForTicker
	os.Remove(ctxWrapper.cfgPath)
	os.Remove(ctxWrapper.savedDBPath)
	os.Remove(ctxWrapper.commonRegoFolder)
	os.Remove(ctxWrapper.defaultRegoFolder)

	getScanService = ctxWrapper.savedGetService
	close(ctxWrapper.buff)
}

func (ctx *ctxWrapper) EvaluateRegoRule(r *routes.InputRoute, input map[string]interface{}) bool {
	if r.Name == "fail_evaluation" {
		return false
	}
	return true
}

func TestLoads(t *testing.T) {
	wrap := ctxWrapper{}
	wrap.setup(cfgData)

	defer wrap.teardown()

	demoCtx := wrap.instance
	err := demoCtx.ApplyFileCfg(wrap.cfgPath, "", wrap.savedDBPath, false)
	if err != nil {
		t.Fatal(err)
	}

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
  tls-verify: false
  project-key: kcv`

	wrap := ctxWrapper{}
	wrap.setup(cfgData)

	defer wrap.teardown()

	demoCtx := wrap.instance

	errStart := demoCtx.ApplyFileCfg(wrap.cfgPath, "", wrap.savedDBPath, false)
	if errStart != nil {
		t.Fatal(errStart)
	}

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
	if _, ok := scanner.(*msgservice.MsgService); !ok {
		t.Error("getScanService() doesn't return an instance of scanservice.ScanService")
	}
}
