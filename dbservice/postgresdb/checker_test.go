package postgresdb

import (
	"log"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	sqlxmock "github.com/zhashkevych/go-sqlxmock"
)

func TestExpiredDates(t *testing.T) {
	tests := []struct {
		name       string
		time       time.Time
		wasDeleted bool
	}{
		{"Time before Now", time.Now().UTC().Add(time.Duration(1) * time.Hour), false},
		{"Time after Now", time.Now().UTC().Add(time.Duration(-1) * time.Hour), true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deleted := false
			savedPsqlConnect := psqlConnect
			psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
				db, mock, err := sqlxmock.Newx()
				if err != nil {
					log.Println("failed to open sqlmock database:", err)
				}
				rows := sqlxmock.NewRows([]string{"date", "messagekey"}).AddRow(test.time, "ttlKeyTest")
				mock.ExpectQuery("SELECT").WillReturnRows(rows)
				return db, err
			}
			savedDeleteRow := deleteRow
			deleteRow = func(db *sqlx.DB, table, id, columnName, value string) error {
				deleted = true
				return nil
			}
			defer func() {
				psqlConnect = savedPsqlConnect
				deleteRow = savedDeleteRow
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
					log.Println("failed to open sqlmock database:", err)
				}
				rows := sqlxmock.NewRows([]string{"size"}).AddRow(test.size)
				mock.ExpectQuery("SELECT").WillReturnRows(rows)
				return db, err
			}
			savedDeleteRowsById := deleteRowsById
			deleteRowsById = func(db *sqlx.DB, table, id string) error {
				deleted = true
				return nil
			}
			defer func() {
				psqlConnect = savedPsqlConnect
				deleteRowsById = savedDeleteRowsById
			}()
			db.SetDbSizeLimit(test.sizeLimit)
			db.CheckSizeLimit()
			if deleted != test.wasDeleted {
				t.Errorf("error deleted rows")
			}
		})
	}
}
