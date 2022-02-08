package dbservice

import (
	"errors"
	"reflect"
	"testing"

	"github.com/aquasecurity/postee/v2/dbservice/postgresdb"
)

func TestConfigurePostgresWithEmptyTenantName(t *testing.T) {
	tests := []struct {
		name          string
		url           string
		tenantName    string
		expectedError error
	}{
		{"happy configuration postgres with url and tenantName", "postgresql://user:secret@localhost", "test-tenantName", nil},
		{"sad configuration without tenantName", "postgresql://user:secret@localhost", "", errConfigPsqlEmptyTenantName},
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

			err := ConfigureDb("", test.url, test.tenantName)
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
