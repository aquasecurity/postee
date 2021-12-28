package postgresdb

import (
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
			t.Errorf("failed to open sqlmock database: %v", err)
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
