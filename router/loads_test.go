package router

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"

	"github.com/aquasecurity/postee/v2/actions"
	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/dbservice"
	"github.com/aquasecurity/postee/v2/msgservice"
	"github.com/aquasecurity/postee/v2/routes"
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
	actionCls   string
	templateCls string
	routeName   string
}

func (ctx *ctxWrapper) MsgHandling(input []byte, action actions.Action, route *routes.InputRoute, inpteval data.Inpteval, aquaServer *string) {
	i := invctn{
		fmt.Sprintf("%T", action),
		fmt.Sprintf("%T", inpteval),
		route.Name,
	}
	ctx.buff <- i
}

func (ctxWrapper *ctxWrapper) setup(cfg string) {
	ctxWrapper.savedDBPath = dbservice.DbPath
	ctxWrapper.savedBaseForTicker = baseForTicker
	ctxWrapper.cfgPath = "cfg_test.yaml"
	ctxWrapper.savedGetService = getScanService
	ctxWrapper.buff = make(chan invctn)

	dbservice.DbPath = "test_webhooks.db"
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

	err = ioutil.WriteFile(ctxWrapper.cfgPath, []byte(cfg), 0644)
	if err != nil {
		log.Printf("Can't write to %s", ctxWrapper.cfgPath)
	}
	ctxWrapper.instance = Instance()
}

func (ctxWrapper *ctxWrapper) teardown() {
	ctxWrapper.instance.Terminate()

	baseForTicker = ctxWrapper.savedBaseForTicker
	os.Remove(ctxWrapper.cfgPath)
	os.Remove(dbservice.DbPath)
	os.Remove(ctxWrapper.commonRegoFolder)
	os.Remove(ctxWrapper.defaultRegoFolder)

	dbservice.ChangeDbPath(ctxWrapper.savedDBPath)
	getScanService = ctxWrapper.savedGetService
	close(ctxWrapper.buff)
}

func (ctx *ctxWrapper) EvaluateRegoRule(r *routes.InputRoute, _ []byte) bool {
	if r.Name == "fail_evaluation" {
		return false
	}
	return true
}

func TestLoads(t *testing.T) {
	t.Skip("FIXME: this test makes an external call")
	cfgData := `
name: tenant
aqua-server: https://demolab.aquasec.com
max-db-size: 13MB #  Max size of DB. <numbers><unit suffix> pattern is used, such as "300MB" or "1GB". If empty or 0 then unlimited
delete-old-data: 7 # delete data older than N day(s).  If empty then we do not delete.d

routes:
- name: route1      #  name must be unique
  input: |
   contains(input.image, "alpine")
   input.vulnerability_summary.critical >= 3

  actions: ["my-slack"]        #  a list of integrations which will receive a scan or an audit event
  template: raw       #  a template for this route
  plugins:
   policy-show-all: true

- name: route2      #  name must be unique
  input: |
   contains(input.image, "alpine")

  actions: ["my-slack"]        #  a list of integrations which will receive a scan or an audit event
  template: raw       #  a template for this route
  plugins:
   policy-show-all: true

templates:
- name: raw
  body: input

actions:
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

	wrap := ctxWrapper{}
	wrap.setup(cfgData)

	defer wrap.teardown()

	demoCtx := wrap.instance
	err := demoCtx.Start(wrap.cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	expectedActionsCnt := 2
	if len(demoCtx.actions) != expectedActionsCnt {
		t.Errorf("There are stopped actions\nWaited: %d\nResult: %d", expectedActionsCnt, len(demoCtx.actions))
	}

	_, ok := demoCtx.actions["jira"]
	if !ok {
		t.Errorf("'jira' action didn't start!")
	}

	expectedSrvUrl := "https://demolab.aquasec.com/#/images/"
	if demoCtx.aquaServer != expectedSrvUrl {
		t.Errorf("Wrong init of AquaServer link.\nWait: %q\nGot: %q", expectedSrvUrl, demoCtx.aquaServer)
	}

	if _, ok := demoCtx.actions["splunk"]; !ok {
		t.Errorf("Action 'splunk' didn't run!")
	}
}
func TestReload(t *testing.T) {
	t.Skip("FIXME: this test makes an external call")
	cfgData := `
name: tenant
aqua-server: https://demolab.aquasec.com
max-db-size: 13MB #  Max size of DB. <numbers><unit suffix> pattern is used, such as "300MB" or "1GB". If empty or 0 then unlimited
delete-old-data: 7 # delete data older than N day(s).  If empty then we do not delete.d

routes:
- name: route1      #  name must be unique
  input: |
   contains(input.image, "alpine")
   input.vulnerability_summary.critical >= 3

  actions: ["my-slack"]        #  a list of integrations which will receive a scan or an audit event
  template: raw       #  a template for this route
  plugins:
   policy-show-all: true

- name: route2      #  name must be unique
  input: |
   contains(input.image, "alpine")

  actions: ["my-slack"]        #  a list of integrations which will receive a scan or an audit event
  template: raw       #  a template for this route
  plugins:
   policy-show-all: true

templates:
- name: raw
  body: input

actions:
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
	errStart := demoCtx.Start(wrap.cfgPath)
	if errStart != nil {
		t.Fatal(errStart)
	}
	expectedActionsCnt := 2
	if len(demoCtx.actions) != expectedActionsCnt {
		t.Errorf("There are stopped actions\nWaited: %d\nResult: %d", expectedActionsCnt, len(demoCtx.actions))
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
	expectedActionsAfterReload := 3

	if len(demoCtx.actions) != expectedActionsAfterReload {
		t.Errorf("There are stopped actions\nWaited: %d\nResult: %d", expectedActionsAfterReload, len(demoCtx.actions))
	}

}

func TestServiceGetters(t *testing.T) {
	scanner := getScanService()
	if _, ok := scanner.(*msgservice.MsgService); !ok {
		t.Error("getScanService() doesn't return an instance of scanservice.ScanService")
	}
}
