package dbservice

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/aquasecurity/postee/dbservice/postgresdb"
)

func TestConfigurateBoltDbPathUsedEnv(t *testing.T) {
	tests := []struct {
		name         string
		dbPath       string
		dbPathInEnv  string
		expectedPath string
	}{
		{"happy configuration BoltDB with dbPath", "database/webhooks.db", "", "database/webhooks.db"},
		{"happy configuration BoltDB with env", "$PATH_TO_DB", "database/envPath/webhooks.db", "database/envPath/webhooks.db"},
		{"happy configuration BoltDB with empty dbPath", "", "", "/server/database/webhooks.db"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.dbPathInEnv != "" {
				oldPathEnv := os.Getenv("PATH_TO_DB")
				defer func() {
					os.Setenv("PATH_TO_DB", oldPathEnv)
				}()
				os.Setenv("PATH_TO_DB", test.dbPathInEnv)
			}

			testInterval := 2
			if err := ConfigureDb(test.dbPath, "", "", &testInterval, 1); err != nil {
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

func TestConfiguratePostgresDbUrlAndId(t *testing.T) {
	tests := []struct {
		name          string
		url           string
		urlInEnv      string
		id            string
		expectedError error
	}{
		{"happy configuration postgres with url", "postgresql://user:secret@localhost", "", "test-id", nil},
		{"happy configuration postgres with env", "$POSTGRES_URL", "postgresql://user:secret@localhost", "test-id", nil},
		{"bad id", "postgresql://user:secret@localhost", "", "", errors.New("error configurate postgresDb: 'tenantId' is empty")},
		{"bad url", "badUrl", "", "test-id", errors.New("badUrl error")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			initPostgresDbSaved := postgresdb.InitPostgresDb
			postgresdb.InitPostgresDb = func(connectUrl string) error {
				if connectUrl == "badUrl" {
					return errors.New("badUrl error")
				}
				return nil
			}
			oldUrlEnv := os.Getenv("POSTGRES_URL")
			os.Setenv("POSTGRES_URL", test.urlInEnv)
			defer func() {
				postgresdb.InitPostgresDb = initPostgresDbSaved
				os.Setenv("POSTGRES_URL", oldUrlEnv)
			}()

			testInterval := 0
			err := ConfigureDb("", test.url, test.id, &testInterval, 1)
			if err != nil {
				if err.Error() != test.expectedError.Error() {
					t.Errorf("Unexpected error, expected: %s, got: %s", test.expectedError, err)
				}
			} else {
				if testInterval != 1 {
					t.Error("test interval error, expected: 1, got: ", testInterval)
				}
				if strings.HasPrefix(test.url, "$") {
					if test.urlInEnv != reflect.Indirect(reflect.ValueOf(Db)).FieldByName("ConnectUrl").Interface() {
						t.Errorf("url's do not match, expected: %s, got: %s", test.url, reflect.Indirect(reflect.ValueOf(Db)).FieldByName("ConnectUrl").Interface())
					}
				} else {
					if test.url != reflect.Indirect(reflect.ValueOf(Db)).FieldByName("ConnectUrl").Interface() {
						t.Errorf("url's do not match, expected: %s, got: %s", test.url, reflect.Indirect(reflect.ValueOf(Db)).FieldByName("ConnectUrl").Interface())
					}
				}
				if test.id != reflect.Indirect(reflect.ValueOf(Db)).FieldByName("Id").Interface() {
					t.Errorf("id's do not match, expected: %s, got: %s", test.url, reflect.Indirect(reflect.ValueOf(Db)).FieldByName("Id").Interface())
				}
			}
		})
	}
}
