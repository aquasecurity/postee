package postgresdb

import (
	"errors"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	sqlxmock "github.com/zhashkevych/go-sqlxmock"
)

var (
	AlpineImageKey    = "sha256:c8bccc0af9571ec0d006a43acb5a8d08c4ce42b6cc7194dd6eb167976f501ef1-alpine:3.8-Docker Hub"
	AlpineImageResult = `{
		"image": "alpine:3.8",
		"registry": "Docker Hub",
		"digest": "sha256:c8bccc0af9571ec0d006a43acb5a8d08c4ce42b6cc7194dd6eb167976f501ef1",
		"previous_digest": "sha256:c8bccc0af9571ec0d006a43acb5a8d08c4ce42b6cc7194dd6eb167976f501ef1",
		"image_assurance_results": {
			"disallowed": true,
			"checks_performed": [
				{
					"control": "max_severity",
					"policy_name": "Default",
					"failed": false
				},
				{
					"control": "trusted_base_images",
					"policy_name": "Default",
					"failed": true
				},
				{
					"control": "max_score",
					"policy_name": "Default",
					"failed": false
				}
			]
		},
		"vulnerability_summary": {
			"total": 2,
			"critical": 0,
			"high": 0,
			"medium": 2,
			"low": 0,
			"negligible": 0,
			"sensitive": 0,
			"malware": 0
		},
		"scan_options": {
			"scan_sensitive_data": true,
			"scan_malware": true
		},
		"resources": [
			{
				"vulnerabilities": [
					{
						"name": "CVE-2018-20679",
						"version": "",
						"fix_version": "",
						"aqua_severity": "medium"
					},
					{
						"name": "CVE-2019-5747",
						"version": "",
						"fix_version": "",
						"aqua_severity": "medium"
					}
				],
				"resource": {
					"name": "busybox",
					"version": "1.28.4-r3"
				}
			}
		]
	}`

	db = NewPostgresDb("tenantName", "postgresql://user:secret@localhost/dbname?sslmode=disable")
)

func TestInitError(t *testing.T) {
	initTablesErr := errors.New("init tables error")
	testConnectErr := errors.New("test connect error")

	savedPsqlConnect := psqlConnect
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		db, mock, err := sqlxmock.Newx()
		if err != nil {
			t.Errorf("failed to open sqlmock database: %v", err)
		}
		mock.ExpectExec("CREATE").WillReturnError(initTablesErr)
		return db, err
	}

	err := InitPostgresDb("connectUrl")
	if !errors.Is(err, initTablesErr) {
		t.Errorf("Unexpected error: expected %s, got %s \n", initTablesErr, err)
	}

	savedTestConnect := testConnect
	testConnect = func(connectUrl string) (*sqlx.DB, error) { return nil, testConnectErr }
	defer func() {
		psqlConnect = savedPsqlConnect
		testConnect = savedTestConnect
	}()
	err = InitPostgresDb("ConnectUrl")
	if !errors.Is(err, testConnectErr) {
		t.Errorf("Unexpected error: expected %s, got %s \n", testConnectErr, err)
	}
}

func TestDeleteRowsByTenantNameAndTime(t *testing.T) {
	tests := []struct {
		name          string
		wasError      bool
		expectedError error
	}{
		{"happy delete rows by tenantName", false, nil},
		{"bad delete row by tenantName", true, errors.New("delete rows error")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
				savedDeleteRowsByTenantName := deleteRowsByTenantName
				defer func() {
					deleteRowsByTenantName = savedDeleteRowsByTenantName
				}()
				db, mock, err := sqlxmock.Newx()
				if err != nil {
					t.Errorf("failed to open sqlmock database: %v", err)
				}
				if test.wasError {
					mock.ExpectExec("DELETE").WillReturnError(test.expectedError)
				} else {
					mock.ExpectExec("DELETE").WillReturnResult(sqlxmock.NewResult(1, 1))
				}
				return db, err
			}
			psqlDb, _ := psqlConnect(db.ConnectUrl)
			err := deleteRowsByTenantNameAndTime(psqlDb, "tenantName", time.Now())
			if test.expectedError != err {
				t.Errorf("Unexpected error, expected: %v, got: %v", test.expectedError, err)
			}
		})
	}
}
func TestDeleteRowsByTenantName(t *testing.T) {
	tests := []struct {
		name          string
		wasError      bool
		expectedError error
	}{
		{"happy delete rows by tenantName", false, nil},
		{"bad delete row by tenantName", true, errors.New("delete rows error")},
	}
	for _, test := range tests {
		psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
			savedDeleteRowsByTenantName := deleteRowsByTenantName
			defer func() {
				deleteRowsByTenantName = savedDeleteRowsByTenantName
			}()
			db, mock, err := sqlxmock.Newx()
			if err != nil {
				t.Errorf("failed to open sqlmock database: %v", err)
			}
			if test.wasError {
				mock.ExpectExec("DELETE").WillReturnError(test.expectedError)
			} else {
				mock.ExpectExec("DELETE").WillReturnResult(sqlxmock.NewResult(1, 1))
			}
			return db, err
		}
		psqlDb, _ := psqlConnect(db.ConnectUrl)
		err := deleteRowsByTenantName(psqlDb, "table", "tenantName")
		if test.expectedError != err {
			t.Errorf("Unexpected error, expected: %v, got: %v", test.expectedError, err)
		}
	}
}

var insertFuncs = []string{
	"insertInTableSharedConfig",
	"insertInTableAggregator",
	"insertInTableName",
	"insertOutputStats",
	"insertCfgCacheSource",
}

func TestInsert(t *testing.T) {
	tests := []struct {
		name          string
		wasQueryError bool
		queryRows     int
		exec          string
		wasExecError  bool
		expectedError error
	}{
		{" happy insert", false, 0, "INSERT", false, nil},
		{" happy update", false, 1, "UPDATE", false, nil},
		{" select error", true, 0, "INSERT", false, errors.New("select error")},
		{" bad insert", false, 0, "INSERT", true, errors.New("bad insert error")},
		{" bad update", false, 1, "UPDATE", true, errors.New("bad update error")},
	}
	for _, insertFunc := range insertFuncs {
		for _, test := range tests {
			t.Run(insertFunc+test.name, func(t *testing.T) {
				savedPsqlConnect := psqlConnect
				psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
					db, mock, err := sqlxmock.Newx()
					if err != nil {
						t.Errorf("failed to open sqlmock database: %v", err)
					}
					if test.wasQueryError {
						mock.ExpectQuery("SELECT").WillReturnError(test.expectedError)
					} else {
						rows := sqlxmock.NewRows([]string{"count"}).AddRow(test.queryRows)
						mock.ExpectQuery("SELECT").WillReturnRows(rows)
					}
					if test.wasExecError {
						mock.ExpectExec(test.exec).WillReturnError(test.expectedError)
					} else {
						mock.ExpectExec(test.exec).WillReturnResult(sqlxmock.NewResult(1, 1))
					}
					return db, err
				}
				defer func() {
					psqlConnect = savedPsqlConnect
				}()

				psqlDb, _ := psqlConnect(db.ConnectUrl)
				err := runInsertFunc(psqlDb, insertFunc)
				if err != nil {
					if !errors.Is(err, test.expectedError) {
						t.Errorf("Unexpected error in %s, expected: %v, got: %v", insertFunc, test.expectedError, err)
					}
				}
			})
		}
	}
}

func TestInsertErrorSelect2Rows(t *testing.T) {
	tests := []struct {
		f             string
		expectedError string
	}{
		{"insertInTableSharedConfig", "error insert in postgresDb. Table:WebhookSharedConfig where tenantName=tenantName, apikeyname=apiKeyName, have 2 rows"},
		{"insertInTableAggregator", "error insert in postgresDb. Table:WebhookAggregator where tenantName=tenantName, output=output, have 2 rows"},
		{"insertInTableName", "error insert in postgresDb. Table:WebhookBucket where tenantName=tenantName, messageKey=messagekey, have 2 rows"},
		{"insertOutputStats", "error insert in postgresDb. Table:WebhookOutputStats where tenantName=tenantName, outputName=outputName, have 2 rows"},
		{"insertCfgCacheSource", "error insert in postgresDb. Table:WebhookCfgCacheSource where tenantName=tenantName, have 2 rows"},
	}
	for _, test := range tests {
		t.Run(test.f, func(t *testing.T) {
			savedPsqlConnect := psqlConnect
			psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
				db, mock, err := sqlxmock.Newx()
				if err != nil {
					t.Errorf("failed to open sqlmock database: %v", err)
				}
				rows := sqlxmock.NewRows([]string{"count"}).AddRow(2)
				mock.ExpectQuery("SELECT").WillReturnRows(rows)
				return db, err
			}
			defer func() {
				psqlConnect = savedPsqlConnect
			}()
			psqlDb, _ := psqlConnect(db.ConnectUrl)
			err := runInsertFunc(psqlDb, test.f)
			if err == nil {
				t.Errorf("no error, expected: %s", test.expectedError)
			} else if err.Error() != test.expectedError {
				t.Errorf("unexpected error, expected: %s got: %v", test.expectedError, err)
			}
		})
	}
}

func runInsertFunc(db *sqlx.DB, funcName string) error {
	switch funcName {
	case "insertInTableSharedConfig":
		return insertInTableSharedConfig(db, "tenantName", "apiKeyName", "value")
	case "insertInTableAggregator":
		return insertInTableAggregator(db, "tenantName", "output", []byte("saving"))
	case "insertInTableName":
		return insertInTableName(db, "tenantName", "messagekey", []byte("messageValue"), &time.Time{})
	case "insertOutputStats":
		return insertOutputStats(db, "tenantName", "outputName", 1)
	case "insertCfgCacheSource":
		return insertCfgCacheSource(db, "tenantName", "cfgfile")
	}
	return nil
}
