package postgresdb

import (
	"testing"
	"time"

	"github.com/aquasecurity/postee/v2/dbservice/dbparam"
	"github.com/jmoiron/sqlx"
	sqlxmock "github.com/zhashkevych/go-sqlxmock"
)

func TestExpiredDates(t *testing.T) {
	tests := []struct {
		name        string
		deleteError bool
		wasDeleted  bool
	}{
		{"happy delete rows", false, true},
		{"bad delete rows", true, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deleted := false
			savedPsqlConnect := psqlConnect
			psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
				db, _, err := sqlxmock.Newx()
				if err != nil {
					t.Errorf("failed to open sqlmock database: %v", err)
				}
				return db, err
			}
			savedDeleteRow := deleteRowsByTenantNameAndTime
			deleteRowsByTenantNameAndTime = func(db *sqlx.DB, tenantName string, t time.Time) error {
				if !test.deleteError {
					deleted = true
				}
				return nil
			}
			defer func() {
				psqlConnect = savedPsqlConnect
				deleteRowsByTenantNameAndTime = savedDeleteRow
			}()
			db.CheckExpiredData()
			if deleted != test.wasDeleted {
				t.Errorf("error deleted rows")
			}
		})
	}
}

func TestSizeLimit(t *testing.T) {
	tests := []struct {
		name       string
		sizeLimit  int
		size       int
		wasDeleted bool
	}{
		{"No size limit", 0, 10, false},
		{"Size less then limit", 5, 10, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deleted := false
			savedPsqlConnect := psqlConnect
			psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
				db, mock, err := sqlxmock.Newx()
				if err != nil {
					t.Errorf("failed to open sqlmock database: %v", err)
				}
				rows := sqlxmock.NewRows([]string{"size"}).AddRow(test.size)
				mock.ExpectQuery("SELECT").WillReturnRows(rows)
				return db, err
			}
			savedDeleteRowsByTenantName := deleteRowsByTenantName
			deleteRowsByTenantName = func(db *sqlx.DB, table, tenantName string) error {
				deleted = true
				return nil
			}
			defer func() {
				psqlConnect = savedPsqlConnect
				deleteRowsByTenantName = savedDeleteRowsByTenantName
			}()
			dbparam.DbSizeLimit = test.sizeLimit
			db.CheckSizeLimit()
			if deleted != test.wasDeleted {
				t.Errorf("error deleted rows")
			}
		})
	}
}
