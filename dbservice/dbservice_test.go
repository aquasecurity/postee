package dbservice

import (
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/aquasecurity/postee/v2/dbservice/postgresdb"
)

func TestConfigurateBoltDbPathUsedEnv(t *testing.T) {
	tests := []struct {
		name         string
		dbPath       string
		expectedPath string
	}{
		{"happy configuration BoltDB with dbPath", "database/webhooks.db", "database/webhooks.db"},
		{"happy configuration BoltDB with empty dbPath", "", "/server/database/webhooks.db"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			testInterval := 2
			if _, err := ConfigureDb(test.dbPath, "", ""); err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if testInterval != 2 {
				t.Error("test interval error, expected: 2, got: ", testInterval)
			}
			if test.expectedPath != reflect.Indirect(reflect.ValueOf(Db)).FieldByName("DbPath").Interface() {
				t.Errorf("paths do not match, expected: %s, got: %s", test.expectedPath, reflect.Indirect(reflect.ValueOf(Db)).FieldByName("DbPath").Interface())
			}
		})
		defer os.RemoveAll("database/")
	}
}

func TestConfiguratePostgresDbUrlAndTenantName(t *testing.T) {
	tests := []struct {
		name          string
		url           string
		tenantName    string
		expectedError error
	}{
		{"happy configuration postgres with url", "postgresql://user:secret@localhost", "test-tenantName", nil},
		{"bad tenantName", "postgresql://user:secret@localhost", "", errConfigPsqlEmptyTenantName},
		{"bad url", "badUrl", "test-tenantName", errors.New("badUrl error")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			initPostgresDbSaved := postgresdb.InitPostgresDb
			postgresdb.InitPostgresDb = func(connectUrl string) error {
				if connectUrl == "badUrl" {
					return test.expectedError
				}
				return nil
			}
			defer func() {
				postgresdb.InitPostgresDb = initPostgresDbSaved
			}()

			_, err := ConfigureDb("", test.url, test.tenantName)
			if err != nil {
				if !errors.Is(err, test.expectedError) {
					t.Errorf("Unexpected error, expected: %s, got: %s", test.expectedError, err)
				}
			} else {
				if test.url != reflect.Indirect(reflect.ValueOf(Db)).FieldByName("ConnectUrl").Interface() {
					t.Errorf("url's do not match, expected: %s, got: %s", test.url, reflect.Indirect(reflect.ValueOf(Db)).FieldByName("ConnectUrl").Interface())
				}
				if test.tenantName != reflect.Indirect(reflect.ValueOf(Db)).FieldByName("TenantName").Interface() {
					t.Errorf("tenantName's do not match, expected: %s, got: %s", test.url, reflect.Indirect(reflect.ValueOf(Db)).FieldByName("TenantName").Interface())
				}
			}
		})
	}
}
