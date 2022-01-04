package postgresdb

import (
	"database/sql"
	"errors"
	"log"
	"testing"

	"github.com/jmoiron/sqlx"
	sqlxmock "github.com/zhashkevych/go-sqlxmock"
)

func TestUpdateCfgCacheSource(t *testing.T) {
	cfgFile := `{"name": "tenant", "aqua-server": "https://myserver.aquasec.com"}`
	savedPsqlConnect := psqlConnect
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		db, mock, err := sqlxmock.Newx()
		if err != nil {
			log.Println("failed to open sqlmock database:", err)
		}
		rows := sqlxmock.NewRows([]string{"cfgFile"}).AddRow(cfgFile)
		mock.ExpectQuery("SELECT").WillReturnRows(rows)
		return db, err
	}
	savedInsertCfgCacheSource := insertCfgCacheSource
	insertCfgCacheSource = func(db *sqlx.DB, tenantName, cfgFile string) error { return nil }
	defer func() {
		psqlConnect = savedPsqlConnect
		insertCfgCacheSource = savedInsertCfgCacheSource
	}()

	if err := UpdateCfgCacheSource(db, "cfgFile"); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	cfg, err := GetCfgCacheSource(db)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if cfgFile != cfg {
		t.Errorf("CfgFiles not equals, expected: %s, got: %s", cfgFile, cfg)
	}
}

func TestGetCfgCacheSourceErrors(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		expectedCfg string
		expectedErr string
	}{
		{"Norows error", sql.ErrNoRows, "{}", ""},
		{"select error", errors.New("select error"), "", "error getting cfg cache source: select error"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			savedPsqlConnect := psqlConnect
			psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
				db, mock, err := sqlxmock.Newx()
				if err != nil {
					log.Println("failed to open sqlmock database:", err)
				}
				mock.ExpectQuery("SELECT").WillReturnError(test.err)
				return db, err
			}
			savedInsertCfgCacheSource := insertCfgCacheSource
			insertCfgCacheSource = func(db *sqlx.DB, tenantName, cfgFile string) error { return nil }
			defer func() {
				psqlConnect = savedPsqlConnect
				insertCfgCacheSource = savedInsertCfgCacheSource
			}()

			cfg, err := GetCfgCacheSource(db)
			if test.expectedErr != "" || err != nil {
				if err.Error() != test.expectedErr {
					t.Errorf("Unexpected err, expected: %v, got: %v", test.expectedErr, err)
				}
			}

			if cfg != test.expectedCfg {
				t.Errorf("Bad cfg, expected: %s, got: %s", test.expectedCfg, cfg)
			}
		})

	}

}
