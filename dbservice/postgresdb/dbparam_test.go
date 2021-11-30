package postgresdb

import (
	"testing"
)

func TestBuildPsqlInfo(t *testing.T) {
	var tests = []struct {
		name             string
		dbName           string
		dbHostName       string
		dbPort           string
		dbUser           string
		dbPassword       string
		dbSslMode        string
		expectedPsqlInfo string
		expectedError    string
	}{
		{"empty dbName", "", "dbHostName", "dbPort", "dbUser", "dbPassword", "dbSslMode",
			"", "can't build psqlInfo, dbName is empty"},
		{"empty dbHostName", "dbName", "", "dbPort", "dbUser", "dbPassword", "dbSslMode",
			"port=dbPort dbname=dbName user=dbUser password=dbPassword sslmode=dbSslMode", ""},
		{"empty dbPort", "dbName", "dbHostName", "", "dbUser", "dbPassword", "dbSslMode",
			"host=dbHostName dbname=dbName user=dbUser password=dbPassword sslmode=dbSslMode", ""},
		{"empty dbUser", "dbName", "dbHostName", "dbPort", "", "dbPassword", "dbSslMode",
			"", "can't build psqlInfo, dbUser is empty"},
		{"empty dbPassword", "dbName", "dbHostName", "dbPort", "dbUser", "", "dbSslMode",
			"host=dbHostName port=dbPort dbname=dbName user=dbUser sslmode=dbSslMode", ""},
		{"empty dbSslMode", "dbName", "dbHostName", "dbPort", "dbUser", "dbPassword", "",
			"host=dbHostName port=dbPort dbname=dbName user=dbUser password=dbPassword sslmode=disable", ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			psqlInfo, err := buildPsqlInfo(test.dbName, test.dbHostName, test.dbPort, test.dbUser, test.dbPassword, test.dbSslMode)
			if err != nil && err.Error() != test.expectedError {
				t.Errorf("Unexpected error for %s, expected %v, got %v", test.name, test.expectedError, err)
			}
			if test.expectedPsqlInfo != psqlInfo {
				t.Errorf("error getting psqlInfo, expected:%s, got:%s", test.expectedPsqlInfo, psqlInfo)
			}
		})
	}
}
