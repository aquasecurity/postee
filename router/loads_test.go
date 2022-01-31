package router

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"

	"github.com/aquasecurity/postee/data"
	"github.com/aquasecurity/postee/dbservice"
	"github.com/aquasecurity/postee/dbservice/boltdb"
	"github.com/aquasecurity/postee/dbservice/postgresdb"
	"github.com/aquasecurity/postee/msgservice"
	"github.com/aquasecurity/postee/outputs"
	"github.com/aquasecurity/postee/routes"
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
	db = boltdb.NewBoltDb()
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
	ctxWrapper.savedDBPath = db.DbPath
	ctxWrapper.savedBaseForTicker = baseForTicker
	ctxWrapper.savedGetService = getScanService
	ctxWrapper.buff = make(chan invctn)

	db.DbPath = "test_webhooks.db"
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
	os.Remove(db.DbPath)
	os.Remove(ctxWrapper.commonRegoFolder)
	os.Remove(ctxWrapper.defaultRegoFolder)

	db.ChangeDbPath(ctxWrapper.savedDBPath)
	getScanService = ctxWrapper.savedGetService
	close(ctxWrapper.buff)
}

func (ctx *ctxWrapper) EvaluateRegoRule(r *routes.InputRoute, _ map[string]interface{}) bool {
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
	err := demoCtx.ApplyFileCfg(wrap.cfgPath, "", "", false)
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

	errStart := demoCtx.ApplyFileCfg(wrap.cfgPath, "", "", false)
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

func TestApplyPostgresCfg(t *testing.T) {
	testTenantSerrings := data.TenantSettings{
		Name:            "TenantName",
		AquaServer:      "https://demolab.aquasec.com",
		DBMaxSize:       13,
		DBRemoveOldData: 7,
		InputRoutes: []routes.InputRoute{
			{
				Name:     "route",
				Outputs:  []string{"slack", "teams"},
				Template: "legacy",
			},
		},
		Outputs: []data.OutputSettings{
			{
				Name:   "slack",
				Type:   "slack",
				Url:    "https://hooks.slack.com/services/TAAAA/BBB/",
				Enable: true,
			},
			{
				Name:   "teams",
				Type:   "teams",
				Url:    "https://outlook.office.com/webhook/",
				Enable: true,
			},
		},
		Templates: []data.Template{
			{
				Name:               "legacy",
				LegacyScanRenderer: "html",
			},
		},
	}
	wrap := ctxWrapper{}
	wrap.init()
	demoCtx := wrap.instance

	savedDb := dbservice.Db
	dbservice.Db = &postgresdb.PostgresDb{}

	postgresUrl := "postgres://User:Password@DbHostName:Port/DbName?sslmode=SslMode"

	savedGetCfgCacheSource := postgresdb.GetCfgCacheSource
	postgresdb.GetCfgCacheSource = func(postgresDb *postgresdb.PostgresDb) (string, error) {
		cfg, _ := json.Marshal(testTenantSerrings)
		return string(cfg), nil
	}

	savedUpdateCfgCacheSource := postgresdb.UpdateCfgCacheSource
	postgresdb.UpdateCfgCacheSource = func(postgresDb *postgresdb.PostgresDb, cfgfile string) error { return nil }

	savedInitPostgresDb := postgresdb.InitPostgresDb
	postgresdb.InitPostgresDb = func(connectUrl string) error { return nil }
	defer func() {
		wrap.teardown()
		dbservice.Db = savedDb
		postgresdb.GetCfgCacheSource = savedGetCfgCacheSource
		postgresdb.InitPostgresDb = savedInitPostgresDb
		postgresdb.UpdateCfgCacheSource = savedUpdateCfgCacheSource
	}()

	err := demoCtx.ApplyPostgresCfg("tenantName", postgresUrl, true)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	expectedOutputsCnt := 2
	if len(demoCtx.outputs) != expectedOutputsCnt {
		t.Errorf("There are stopped outputs\nWaited: %d\nResult: %d", expectedOutputsCnt, len(Instance().outputs))
	}

	if testTenantSerrings.Outputs[0].Name != Instance().databaseCfgCacheSource.Outputs[0].Name {
		t.Errorf("Output names are not equals, expected: %s, got: %s", testTenantSerrings.Outputs[0].Name, Instance().databaseCfgCacheSource.Outputs[0].Name)
	}
}
