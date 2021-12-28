package router

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/postee/data"
	"github.com/aquasecurity/postee/dbservice"
	"github.com/aquasecurity/postee/dbservice/boltdb" //nolint - used to get db type in TestConfigFuncs
	"github.com/aquasecurity/postee/dbservice/postgresdb"
	"github.com/aquasecurity/postee/outputs" //nolint - used to get Output type in TestEditOutput
	"github.com/aquasecurity/postee/routes"
	"github.com/stretchr/testify/assert"
)

func TestAquaServerUrl(t *testing.T) {
	AquaServerUrl("http://localhost:8080")
	assert.Equal(t, "http://localhost:8080/#/images/", Instance().aquaServer, "AquaServerUrl")

}

var outputSettings = &data.OutputSettings{
	Type:   "slack",
	Name:   "my-slack",
	Url:    "https://hooks.slack.com/services/TAAAA/BBB/",
	Enable: true,
}

var outputSettingsTeams = &data.OutputSettings{
	Type:   "teams",
	Name:   "ms-teams",
	Url:    "https://outlook.office.com/webhook/",
	Enable: true,
}

var inputRoute = &routes.InputRoute{
	Name:     "my-route",
	Outputs:  []string{"my-slack"},
	Template: "legacy-slack",
}

var inputRouteJira = &routes.InputRoute{
	Name:     "my-jira",
	Outputs:  []string{"my-jira"},
	Template: "legacy-jira",
}

var inputRouteHtml = &routes.InputRoute{
	Name:     "my-html",
	Outputs:  []string{"my-html"},
	Template: "legacy",
}

var template = &data.Template{
	Name:               "legacy",
	LegacyScanRenderer: "html",
}

var templateSlack = &data.Template{
	Name:               "legacy-slack",
	LegacyScanRenderer: "slack",
}

func TestAddOutput(t *testing.T) {
	if len(Instance().outputs) > 0 {
		Instance().cleanInstance()
	}
	defer Instance().cleanInstance()

	if err := AddOutput(outputSettings); err != nil {
		t.Errorf("Can't add output: %v", err)
	}
	assert.Equal(t, 1, len(Instance().outputs), "one output expected")
	assert.Contains(t, Instance().outputs, "my-slack")
	assert.Equal(t, "my-slack", Instance().outputs["my-slack"].GetName(), "check name failed")
	assert.Equal(t, "*outputs.SlackOutput", fmt.Sprintf("%T", Instance().outputs["my-slack"]), "check name failed")

}

func TestDeleteOutput(t *testing.T) {
	if len(Instance().inputRoutes) > 0 || len(Instance().outputs) > 0 {
		Instance().cleanInstance()
	}
	defer Instance().cleanInstance()

	if err := AddOutput(outputSettings); err != nil {
		t.Errorf("Can't add output: %v", err)
	}
	if err := AddOutput(outputSettingsTeams); err != nil {
		t.Errorf("Can't add output: %v", err)
	}
	assert.Equal(t, 2, len(Instance().outputs), "two output expected")

	AddRoute(&routes.InputRoute{Name: "my-route", Outputs: []string{"my-slack", "ms-teams"}})
	assert.Equal(t, 2, len(Instance().inputRoutes["my-route"].Outputs), "two output expected")

	if err := DeleteOutput("my-slack"); err != nil {
		t.Errorf("Can't delte output: %v", err)
	}
	assert.Equal(t, 1, len(Instance().outputs), "one outputs expected")
	assert.NotContains(t, Instance().outputs, "my-slack")

	assert.Equal(t, 1, len(Instance().inputRoutes["my-route"].Outputs), "one output in inputRoute expected")
	assert.NotContains(t, Instance().inputRoutes["my-route"].Outputs, "my-slack")

}
func TestEditOutput(t *testing.T) {
	if len(Instance().outputs) > 0 {
		Instance().cleanInstance()
	}
	defer Instance().cleanInstance()
	modifiedUrl := "https://hooks.slack.com/services/TAAAA/XXX/"
	expectedError := "output badName is not found"

	if err := AddOutput(outputSettings); err != nil {
		t.Errorf("Can't add output: %v", err)
	}
	assert.Equal(t, 1, len(Instance().outputs), "one output expected")

	s := Instance().outputs["my-slack"].CloneSettings()

	s.Url = modifiedUrl

	if err := UpdateOutput(s); err != nil {
		t.Errorf("Can't update output: %v", err)
	}

	assert.Equal(t, 1, len(Instance().outputs), "one output expected")
	assert.Equal(t, modifiedUrl, Instance().outputs["my-slack"].(*outputs.SlackOutput).Url, "url is updated")

	err := UpdateOutput(&data.OutputSettings{Name: "badName"})
	if err != nil && err.Error() != expectedError {
		t.Errorf("unexpected error, expected: %v, got: %v", expectedError, err)
	}
}
func TestListOutput(t *testing.T) {
	if len(Instance().outputs) > 0 {
		Instance().cleanInstance()
	}
	defer Instance().cleanInstance()

	if err := AddOutput(outputSettings); err != nil {
		t.Errorf("Unexpected AddOutput error: %v", err)
	}
	assert.Equal(t, 1, len(Instance().outputs), "one output expected")

	outputs := ListOutputs()

	assert.Equal(t, 1, len(outputs), "one output expected")

	r := outputs[0]

	assert.Equal(t, "my-slack", r.Name, "check name failed")
	assert.Equal(t, "slack", r.Type, "check type failed")
	assert.True(t, r.Enable, "output must be enabled")
}

func TestAddRoute(t *testing.T) {
	if len(Instance().inputRoutes) > 0 {
		Instance().cleanInstance()
	}
	defer Instance().cleanInstance()

	AddRoute(inputRoute)
	assert.Equal(t, 1, len(Instance().inputRoutes), "one route expected")
	assert.Contains(t, Instance().inputRoutes, "my-route")
	assert.Equal(t, "my-route", Instance().inputRoutes["my-route"].Name, "check name failed")
	assert.Equal(t, "*routes.InputRoute", fmt.Sprintf("%T", Instance().inputRoutes["my-route"]), "check name failed")
}

func TestDeleteRoute(t *testing.T) {
	if len(Instance().inputRoutes) > 0 {
		Instance().cleanInstance()
	}
	defer Instance().cleanInstance()

	AddRoute(inputRoute)
	AddRoute(inputRouteJira)
	AddRoute(inputRouteHtml)
	assert.Equal(t, 3, len(Instance().inputRoutes), "three route expected")

	if err := DeleteRoute("my-route"); err != nil {
		t.Errorf("Unexpected DeleteRoute error: %v", err)
	}
	assert.Equal(t, 2, len(Instance().inputRoutes), "two routes expected")
	assert.NotContains(t, Instance().inputRoutes, "my-route")
}

func TestEditRoute(t *testing.T) {
	if len(Instance().inputRoutes) > 0 {
		Instance().cleanInstance()
	}
	defer Instance().cleanInstance()
	modifiedTemplate := "vuls-slack"
	expectedError := "output badName is not found"

	AddRoute(inputRoute)
	assert.Equal(t, 1, len(Instance().inputRoutes), "one route expected")

	savedTempalate := *Instance().inputRoutes["my-route"]
	r := Instance().inputRoutes["my-route"]
	r.Template = modifiedTemplate
	defer func() {
		*Instance().inputRoutes["my-route"] = savedTempalate
	}()

	if err := UpdateRoute(r); err != nil {
		t.Errorf("Unexpected AddTemplate error: %v", err)
	}

	assert.Equal(t, 1, len(Instance().inputRoutes), "one route expected")
	assert.Equal(t, modifiedTemplate, Instance().inputRoutes["my-route"].Template, "template is updated")

	err := UpdateRoute(&routes.InputRoute{Name: "badName"})
	if err != nil && err.Error() != expectedError {
		t.Errorf("unexpected error, expected: %v, got: %v", expectedError, err)
	}
}

func TestListRoute(t *testing.T) {
	if len(Instance().inputRoutes) > 0 {
		Instance().cleanInstance()
	}
	defer Instance().cleanInstance()

	routes := ListRoutes()
	assert.Equal(t, 0, len(routes), "no route expected")

	AddRoute(inputRoute)
	assert.Equal(t, 1, len(Instance().inputRoutes), "one route expected")

	routes = ListRoutes()

	assert.Equal(t, 1, len(routes), "one route expected")

	r := routes[0]

	assert.Equal(t, "my-route", r.Name, "check name failed")
	assert.Equal(t, "my-slack", r.Outputs[0], "check output failed")
	assert.Equal(t, "legacy-slack", r.Template, "check template failed")
}

func TestAddTemplate(t *testing.T) {
	if len(Instance().templates) > 0 {
		Instance().cleanInstance()
	}
	defer Instance().cleanInstance()

	if err := AddTemplate(template); err != nil {
		t.Errorf("Unexpected AddTemplate error: %v", err)
	}
	assert.Equal(t, 1, len(Instance().templates), "one template expected")
	assert.Contains(t, Instance().templates, "legacy")
	assert.Equal(t, "*formatting.legacyScnEvaluator", fmt.Sprintf("%T", Instance().templates["legacy"]), "check name failed")
}

func TestAddTemplateFromFile(t *testing.T) {
	if len(Instance().templates) > 0 {
		Instance().cleanInstance()
	}
	defer Instance().cleanInstance()
	regoString := `package postee
	default hello = false

hello {
    m := input.message
    m == "world"
}`
	err := ioutil.WriteFile("./testFile", []byte(regoString), 0644)
	if err != nil {
		t.Errorf("error write file: %v", err)
	}
	defer os.Remove("./testFile")
	err = AddRegoTemplateFromFile("rego-template", "testFile")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	assert.Equal(t, 1, len(Instance().templates), "one template expected")
	assert.Contains(t, Instance().templates, "rego-template")
	assert.Equal(t, "*regoservice.regoEvaluator", fmt.Sprintf("%T", Instance().templates["rego-template"]), "check evaluator failed")
}

func TestDeleteTemplate(t *testing.T) {
	if len(Instance().inputRoutes) > 0 || len(Instance().templates) > 0 {
		Instance().cleanInstance()
	}
	defer Instance().cleanInstance()

	if err := AddTemplate(template); err != nil {
		t.Errorf("Unexpected AddTemplate error: %v", err)
	}

	if err := AddTemplate(templateSlack); err != nil {
		t.Errorf("Unexpected AddTemplate error: %v", err)
	}
	assert.Equal(t, 2, len(Instance().templates), "two template expected")
	AddRoute(&routes.InputRoute{Name: "my-route", Template: "legacy"})
	assert.Equal(t, "legacy", Instance().inputRoutes["my-route"].Template, "one template expected")

	if err := DeleteTemplate("legacy"); err != nil {
		t.Errorf("Unexpected DeleteTemplate error: %v", err)
	}
	assert.Equal(t, 1, len(Instance().templates), "one templates expected")
	assert.NotContains(t, Instance().templates, "legacy")
	assert.Equal(t, "", Instance().inputRoutes["my-route"].Template, "no template expected")
}

func TestEditTemplate(t *testing.T) {
	if len(Instance().templates) > 0 {
		Instance().cleanInstance()
	}
	defer Instance().cleanInstance()
	expectedError := "template badName is not found"

	if err := AddTemplate(template); err != nil {
		t.Errorf("Unexpected AddTemplate error: %v", err)
	}
	assert.Equal(t, 1, len(Instance().templates), "one template expected")
	assert.Equal(t, "*formatting.legacyScnEvaluator", fmt.Sprintf("%T", Instance().templates["legacy"]), "legacyScnEvaluator expected")

	templ := template

	templ.LegacyScanRenderer = ""
	templ.Body = `package postee`

	err := UpdateTemplate(templ)
	if err != nil {
		t.Errorf("unexpected errpr: %v", err)
	}

	assert.Equal(t, 1, len(Instance().templates), "one template expected")
	assert.Equal(t, "*regoservice.regoEvaluator", fmt.Sprintf("%T", Instance().templates["legacy"]), "ScanRenderer is updated")

	err = UpdateTemplate(&data.Template{Name: "badName"})
	if err != nil && err.Error() != expectedError {
		t.Errorf("unexpected error, expected: %v, got: %v", expectedError, err)
	}
}

func TestListTemplate(t *testing.T) {
	if len(Instance().templates) > 0 {
		Instance().cleanInstance()
	}
	defer Instance().cleanInstance()

	if err := AddTemplate(template); err != nil {
		t.Errorf("Unexpected AddTemplate error: %v", err)
	}
	assert.Equal(t, 1, len(Instance().templates), "one route expected")

	templates := ListTemplates()

	assert.Equal(t, 1, len(templates), "one route expected")

	templ := templates[0]

	assert.Equal(t, "legacy", templ, "check name failed")
}

func TestSetInputCallbackFunc(t *testing.T) {
	if len(Instance().inputCallBacks) > 0 || Instance().inputCallBacks == nil {
		Instance().cleanInstance()
	}
	defer Instance().cleanInstance()

	inputCallbackFunc := InputCallbackFunc(func(inputMessage map[string]interface{}) bool { return false })

	AddRoute(inputRoute)
	assert.Equal(t, 0, len(Instance().inputCallBacks), "no inputCallBack expected")

	SetInputCallbackFunc("my-route", inputCallbackFunc)
	assert.Equal(t, 1, len(Instance().inputCallBacks), "one inputCallBack expected")
}

func TestConfigFuncs(t *testing.T) {
	if len(Instance().inputRoutes) > 0 || len(Instance().outputs) > 0 || len(Instance().templates) > 0 {
		Instance().cleanInstance()
	}
	tests := []struct {
		funcName     string
		f            func() error
		tenantName   string
		clearCfg     bool
		templateName string
		outputName   string
		routeName    string
		dbPath       string
		psqlUrl      string
	}{
		{"WithDefaultConfig", withDefaultConfigTest, "", false, "raw", "my-slack", "route1", "./webhooks.db", ""},
		{"WithFileConfig", withFileConfigTest, "", false, "raw", "my-slack", "route1", "./webhooks.db", ""},
		{"WithDefaultConfigAndDbPath", withDefaultConfigAndDbPathTest, "", false, "raw", "my-slack", "route1", "test/webhooks.db", ""},
		{"WithFileConfigAndDbPath", withFileConfigAndDbPathTest, "", false, "raw", "my-slack", "route1", "test/webhooks.db", ""},
		{"WithNewConfig", withNewConfigTest, "", true, "", "", "", "./webhooks.db", ""},
		{"WithNewConfigAndDbPath", withNewConfigAndDbPathTest, "", true, "", "", "", "test/webhooks.db", ""},
		{"WithPostgresParams", withPostgresParamsTest, "ParamsTenantName", true, "", "", "", "", "postgres://ParamsUser:ParamsPassword@ParamsDbHostName:543/ParamsDbName?sslmode=ParamsSslMode"},
		{"WithPostgresUrl", withPostgresUrlTest, "tenantName", true, "", "", "", "", "postgres://ParamsUser:ParamsPassword@ParamsDbHostName:543/ParamsDbName?sslmode=ParamsSslMode"},
	}
	for _, test := range tests {
		t.Run("test "+test.funcName, func(t *testing.T) {
			defer func() {
				Instance().cleanInstance()
				dbservice.Db = nil
			}()

			err := test.f()
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if test.clearCfg {
				assert.Equal(t, 0, len(Instance().templates), "no template expected")
				assert.Equal(t, 0, len(Instance().outputs), "no output expected")
				assert.Equal(t, 0, len(Instance().inputRoutes), "no route expected")
			} else {
				assert.Equal(t, 1, len(Instance().templates), "one template expected")
				assert.Contains(t, Instance().templates, test.templateName)

				assert.Equal(t, 1, len(Instance().outputs), "one output expected")
				assert.Contains(t, Instance().outputs, test.outputName)
				assert.Equal(t, test.outputName, Instance().outputs[test.outputName].GetName(), "check name failed")

				assert.Equal(t, 1, len(Instance().inputRoutes), "one route expected")
				assert.Contains(t, Instance().inputRoutes, test.routeName)
				assert.Contains(t, Instance().inputRoutes[test.routeName].Outputs, test.outputName)
				assert.Equal(t, test.templateName, Instance().inputRoutes[test.routeName].Template, "one template expected")
			}
			if postgresDb, ok := dbservice.Db.(*postgresdb.PostgresDb); ok {
				assert.Equal(t, test.psqlUrl, postgresDb.ConnectUrl, "url configured")
				assert.Equal(t, test.tenantName, postgresDb.TenantName, "tenantName configured")
			}
			if boltDb, ok := dbservice.Db.(*boltdb.BoltDb); ok {
				assert.Equal(t, test.dbPath, boltDb.DbPath, "dbPath configured")
			}
		})
	}
}

var (
	cfgPath    = "test/cfg.yaml"
	tenantName = "tenantName"
	dbPath     = "test/webhooks.db"

	cfg = `Name: tenant

routes:
- name: route1
  outputs: ["my-slack"]
  template: raw
  plugins:
   Policy-Show-All: true

templates:
- name: raw
  body: |
   package postee
   result:=input

outputs:
- name: my-slack
  type: slack
  enable: true
  url: https://hooks.slack.com/services/ABCDF/1234/TTT`
)

var withDefaultConfigTest = func() error {
	if err := createTestCfg(defaultConfigPath); err != nil {
		return err
	}
	if err := WithDefaultConfig(); err != nil {
		return err
	}
	defer func() {
		os.Remove(defaultDbPath)
		os.RemoveAll(filepath.Dir(defaultConfigPath))
	}()
	return nil
}

var withFileConfigTest = func() error {
	if err := createTestCfg(cfgPath); err != nil {
		return err
	}
	if err := WithFileConfig(cfgPath); err != nil {
		return err
	}
	defer func() {
		os.Remove(defaultDbPath)
		os.RemoveAll(filepath.Dir(cfgPath))
	}()
	return nil
}

var withNewConfigTest = func() error {
	if err := WithNewConfig(tenantName); err != nil {
		return err
	}
	defer os.RemoveAll(filepath.Dir(dbPath))
	return nil
}

var withNewConfigAndDbPathTest = func() error {
	if err := WithNewConfigAndDbPath(tenantName, dbPath); err != nil {
		return err
	}
	defer os.RemoveAll(filepath.Dir(dbPath))
	return nil
}

var withFileConfigAndDbPathTest = func() error {
	if err := createTestCfg(cfgPath); err != nil {
		return err
	}
	if err := WithFileConfigAndDbPath(cfgPath, dbPath); err != nil {
		return err
	}
	defer func() {
		os.RemoveAll(filepath.Dir(dbPath))
		os.RemoveAll(filepath.Dir(cfgPath))
	}()
	return nil
}

var withDefaultConfigAndDbPathTest = func() error {
	if err := createTestCfg(defaultConfigPath); err != nil {
		return err
	}
	if err := WithDefaultConfigAndDbPath(dbPath); err != nil {
		return err
	}
	defer func() {
		os.RemoveAll(filepath.Dir(dbPath))
		os.RemoveAll(filepath.Dir(defaultConfigPath))
	}()
	return nil
}

var withPostgresParamsTest = func() error {
	savedInitPostgresDb := postgresdb.InitPostgresDb
	postgresdb.InitPostgresDb = func(connectUrl string) error { return nil }
	savedGetCfgCacheSource := postgresdb.GetCfgCacheSource
	postgresdb.GetCfgCacheSource = func(postgresDb *postgresdb.PostgresDb) (string, error) {
		j, _ := json.Marshal(outputSettings)
		return string(j), nil
	}
	defer func() {
		postgresdb.InitPostgresDb = savedInitPostgresDb
		postgresdb.GetCfgCacheSource = savedGetCfgCacheSource
	}()
	err := WithPostgresParams("ParamsTenantName", "ParamsDbName", "ParamsDbHostName", "543", "ParamsUser", "ParamsPassword", "ParamsSslMode")
	if err != nil {
		return err
	}
	return nil
}

var withPostgresUrlTest = func() error {
	savedInitPostgresDb := postgresdb.InitPostgresDb
	postgresdb.InitPostgresDb = func(connectUrl string) error { return nil }
	savedGetCfgCacheSource := postgresdb.GetCfgCacheSource
	postgresdb.GetCfgCacheSource = func(postgresDb *postgresdb.PostgresDb) (string, error) { return "", nil }
	defer func() {
		postgresdb.InitPostgresDb = savedInitPostgresDb
		postgresdb.GetCfgCacheSource = savedGetCfgCacheSource
	}()
	psqlUrl := "postgres://ParamsUser:ParamsPassword@ParamsDbHostName:543/ParamsDbName?sslmode=ParamsSslMode"
	if err := WithPostgresUrl(tenantName, psqlUrl); err != nil {
		return err
	}
	return nil
}

func createTestCfg(cfgPath string) error {
	_, err := os.Stat(filepath.Dir(cfgPath))
	if err != nil {
		if os.IsNotExist(err) {
			err := os.Mkdir(filepath.Dir(cfgPath), os.ModePerm)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	err = ioutil.WriteFile(cfgPath, []byte(cfg), 0644)
	if err != nil {
		return err
	}
	return nil
}

func TestBuildPosgresUrl(t *testing.T) {
	tests := []struct {
		caseDesc    string
		username    string
		password    string
		port        string
		dbName      string
		dbHostName  string
		dbSslMode   string
		expectedUrl string
	}{
		{
			"all parameters specified",
			"admin",
			"admin",
			"5433",
			"postee",
			"localhost",
			"prefer",
			"postgres://admin:admin@localhost:5433/postee?sslmode=prefer",
		},
		{
			"minimal parameters",
			"admin",
			"admin",
			"",
			"postee",
			"localhost",
			"",
			"postgres://admin:admin@localhost/postee",
		},
	}

	for _, test := range tests {
		t.Run(test.caseDesc, func(t *testing.T) {
			url := buildPostgresUrl(test.dbName, test.dbHostName, test.port, test.username, test.password, test.dbSslMode)
			assert.Equal(t, test.expectedUrl, url)
		})
	}

}

func TestSaveLoadCfgInPostgres(t *testing.T) {
	savedCfgInPsql := ""
	expectedCfgJson := `{"name":"tenantName","aqua-server":"https://myserver.aquasec.com","outputs":null,"routes":null,"templates":null}`
	router := Router{
		databaseCfgCacheSource: &data.TenantSettings{
			Name:       "tenantName",
			AquaServer: "https://myserver.aquasec.com",
		},
	}
	dbservice.Db = postgresdb.NewPostgresDb("tenantName", "connectUrl")
	savedUpdateCfgCacheSource := postgresdb.UpdateCfgCacheSource
	postgresdb.UpdateCfgCacheSource = func(postgresDb *postgresdb.PostgresDb, cfgfile string) error {
		savedCfgInPsql = cfgfile
		return nil
	}
	savedGetCfgCacheSource := postgresdb.GetCfgCacheSource
	postgresdb.GetCfgCacheSource = func(postgresDb *postgresdb.PostgresDb) (string, error) {
		return savedCfgInPsql, nil
	}
	defer func() {
		postgresdb.UpdateCfgCacheSource = savedUpdateCfgCacheSource
		postgresdb.GetCfgCacheSource = savedGetCfgCacheSource
	}()

	if err := router.saveCfgCacheSourceInPostgres(); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if expectedCfgJson != savedCfgInPsql {
		t.Errorf("cfg marshal error, expected: %s, got: %s", expectedCfgJson, savedCfgInPsql)
	}
	tenant, err := router.loadCfgCacheSourceFromPostgres()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if router.databaseCfgCacheSource.Name != tenant.Name {
		t.Errorf("names are not equals, expected: %s, got: %s", router.databaseCfgCacheSource.Name, tenant.Name)
	}
	if router.databaseCfgCacheSource.AquaServer != tenant.AquaServer {
		t.Errorf("AquaServers are not equals, expected: %s, got: %s", router.databaseCfgCacheSource.AquaServer, tenant.AquaServer)
	}
}
