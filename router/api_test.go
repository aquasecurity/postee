package router

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/postee/data"
	"github.com/aquasecurity/postee/dbservice"
	"github.com/aquasecurity/postee/dbservice/postgresdb"
	"github.com/aquasecurity/postee/outputs"
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

func TestAddOutput(t *testing.T) {
	AddOutput(outputSettings)
	assert.Equal(t, 1, len(Instance().outputs), "one output expected")
	assert.Contains(t, Instance().outputs, "my-slack")
	assert.Equal(t, "my-slack", Instance().outputs["my-slack"].GetName(), "check name failed")
	assert.Equal(t, "*outputs.SlackOutput", fmt.Sprintf("%T", Instance().outputs["my-slack"]), "check name failed")

}

func TestDeleteOutput(t *testing.T) {
	AddOutput(outputSettings)
	assert.Equal(t, 1, len(Instance().outputs), "one output expected")

	DeleteOutput("my-slack")
	assert.Equal(t, 0, len(Instance().outputs), "no outputs expected")

}
func TestEditOutput(t *testing.T) {
	modifiedUrl := "https://hooks.slack.com/services/TAAAA/XXX/"
	AddOutput(outputSettings)
	assert.Equal(t, 1, len(Instance().outputs), "one output expected")

	s := Instance().outputs["my-slack"].CloneSettings()

	s.Url = modifiedUrl

	UpdateOutput(s)

	assert.Equal(t, 1, len(Instance().outputs), "one output expected")
	assert.Equal(t, modifiedUrl, Instance().outputs["my-slack"].(*outputs.SlackOutput).Url, "url is updated")

}
func TestListOutput(t *testing.T) {
	AddOutput(outputSettings)
	assert.Equal(t, 1, len(Instance().outputs), "one output expected")

	outputs := ListOutputs()

	assert.Equal(t, 1, len(outputs), "one output expected")

	r := outputs[0]

	assert.Equal(t, "my-slack", r.Name, "check name failed")
	assert.Equal(t, "slack", r.Type, "check type failed")
	assert.True(t, r.Enable, "output must be enabled")

}

//TODO templates
//TODO routes

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
