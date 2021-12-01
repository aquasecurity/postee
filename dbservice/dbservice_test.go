package dbservice

import (
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/aquasecurity/postee/dbservice/postgresdb"
)

func TestConfigurateBoltDbPath(t *testing.T) {
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
			oldPathEnv := os.Getenv("PATH_TO_BOLTDB")
			defer func() {
				os.Setenv("PATH_TO_BOLTDB", oldPathEnv)
			}()
			os.Setenv("PATH_TO_BOLTDB", test.dbPath)

			testInterval := 2
			if err := ConfigurateDb("id", &testInterval, 1); err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if testInterval != 2 {
				t.Error("test interval error, expected: 2, got: ", testInterval)
			}
			if test.expectedPath != reflect.Indirect(reflect.ValueOf(Db)).FieldByName("DbPath").Interface() {
				t.Errorf("paths do not match, expected: %s, got: %s", test.expectedPath, reflect.Indirect(reflect.ValueOf(Db)).FieldByName("DbPath").Interface())
			}

		})
	}
}

func TestConfiguratePostgresDbUrlAndId(t *testing.T) {
	tests := []struct {
		name          string
		url           string
		id            string
		expectedError error
	}{
		{"happy configuration", "postgresql://user:secret@localhost", "test-id", nil},
		{"bad id", "postgresql://user:secret@localhost", "", errors.New("error configurate postgresDb: 'id' is empty")},
		{"bad url", "badUrl", "test-id", errors.New("badUrl error")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testConnectSaved := postgresdb.TestConnect
			postgresdb.TestConnect = func(connectUrl string) error {
				if connectUrl == "badUrl" {
					return errors.New("badUrl error")
				}
				return nil
			}
			defer func() {
				postgresdb.TestConnect = testConnectSaved
			}()
			oldUrlEnv := os.Getenv("POSTGRES_URL")
			defer func() {
				os.Setenv("POSTGRES_URL", oldUrlEnv)
			}()
			os.Setenv("POSTGRES_URL", test.url)

			testInterval := 0
			err := ConfigurateDb(test.id, &testInterval, 1)
			if err != nil {
				if err.Error() != test.expectedError.Error() {
					t.Errorf("Unexpected error, expected: %s, got: %s", test.expectedError, err)
				}
			} else {
				if testInterval != 1 {
					t.Error("test interval error, expected: 1, got: ", testInterval)
				}
				if test.url != reflect.Indirect(reflect.ValueOf(Db)).FieldByName("ConnectUrl").Interface() {
					t.Errorf("url's do not match, expected: %s, got: %s", test.url, reflect.Indirect(reflect.ValueOf(Db)).FieldByName("ConnectUrl").Interface())
				}
				if test.id != reflect.Indirect(reflect.ValueOf(Db)).FieldByName("Id").Interface() {
					t.Errorf("id's do not match, expected: %s, got: %s", test.url, reflect.Indirect(reflect.ValueOf(Db)).FieldByName("Id").Interface())
				}
			}
		})
	}
}
