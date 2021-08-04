package router

import (
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/aquasecurity/postee/data"
	"github.com/aquasecurity/postee/dbservice"
	"github.com/aquasecurity/postee/msgservice"
	"github.com/aquasecurity/postee/outputs"
	"github.com/aquasecurity/postee/routes"
)

var (
	cfgData *TenantSettings = &TenantSettings{

		AquaServer:      "https://demolab.aquasec.com",
		DBMaxSize:       13,
		DBRemoveOldData: 7,

		InputRoutes: []routes.InputRoute{{

			Name: "route1",
			Input: `
contains(input.image, "alpine")
input.vulnerability_summary.critical >= 3
 `,
			Outputs:  []string{"my-slack"},
			Template: "raw",
			Plugins: routes.Plugins{
				PolicyShowAll: true,
			},
		}, {

			Name: "route2",
			Input: `
contains(input.image, "alpine")
 `,
			Outputs:  []string{"my-slack"},
			Template: "raw",
			Plugins: routes.Plugins{
				PolicyShowAll: true,
			},
		}},
		Templates: []Template{
			{
				Name: "raw",
				Body: "input",
			},
		},
		Outputs: []OutputSettings{
			{
				Name:      "splunk",
				Type:      "splunk",
				Enable:    true,
				Url:       "http://localhost:8088",
				Token:     "00aac750-a69c-4ebb-8771-41905f7369dd",
				SizeLimit: 1000,
			},
			{
				Name:       "jira",
				Type:       "jira",
				Enable:     true,
				Url:        "https://afdesk.atlassian.net/",
				User:       "admin",
				Password:   "admin",
				TlsVerify:  false,
				ProjectKey: "kcv",
			},
		},
	}
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
}

func (ctx *ctxWrapper) MsgHandling(input []byte, output outputs.Output, route *routes.InputRoute, inpteval data.Inpteval, aquaServer *string) {
	i := invctn{
		fmt.Sprintf("%T", output),
		fmt.Sprintf("%T", inpteval),
		route.Name,
	}
	ctx.buff <- i
}

func (ctxWrapper *ctxWrapper) setup(settings *TenantSettings) {
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

	ctxWrapper.instance = New(settings)
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

func TestLoads(t *testing.T) {
	wrap := ctxWrapper{}
	wrap.setup(cfgData)

	defer wrap.teardown()

	demoCtx := wrap.instance

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

func TestServiceGetters(t *testing.T) {
	scanner := getScanService()
	if _, ok := scanner.(*msgservice.MsgService); !ok {
		t.Error("getScanService() doesn't return an instance of scanservice.ScanService")
	}
}
