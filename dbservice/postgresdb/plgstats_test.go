package postgresdb

import (
	"database/sql"
	"log"
	"testing"

	"github.com/jmoiron/sqlx"
	sqlxmock "github.com/zhashkevych/go-sqlxmock"
)

func TestRegisterPlgnInvctn(t *testing.T) {
	receivedKey := 0
	savedInsertOutputStats := insertOutputStats
	insertOutputStats = func(db *sqlx.DB, tenantName, outputName string, amount int) error {
		receivedKey = amount
		return nil
	}
	savedPsqlConnect := psqlConnect
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		db, mock, err := sqlxmock.Newx()
		if err != nil {
			log.Println("failed to open sqlmock database:", err)
		}
		rows := sqlxmock.NewRows([]string{"amount"}).AddRow(receivedKey)
		mock.ExpectQuery("SELECT").WillReturnRows(rows)
		return db, err
	}
	defer func() {
		insertOutputStats = savedInsertOutputStats
		psqlConnect = savedPsqlConnect
	}()

	expectedCnt := 3
	keyToTest := "test"
	for i := 0; i < expectedCnt; i++ {
		if err := db.RegisterPlgnInvctn(keyToTest); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	}
	if receivedKey != expectedCnt {
		t.Errorf("Persisted count doesn't match expected. Expected %d, got %d\n", receivedKey, expectedCnt)
	}
}

func TestRegisterPlgnInvctnErrors(t *testing.T) {
	var tests = []struct {
		name        string
		errIn       error
		expectedErr error
	}{
		{"No result rows error", sql.ErrNoRows, nil},
		{"Other errors", sql.ErrConnDone, sql.ErrConnDone},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			savedInsertOutputStats := insertOutputStats
			insertOutputStats = func(db *sqlx.DB, tenantName, outputName string, amount int) error { return nil }
			savedPsqlConnect := psqlConnect
			psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
				db, mock, err := sqlxmock.Newx()
				if err != nil {
					log.Println("failed to open sqlmock database:", err)
				}
				mock.ExpectQuery("SELECT").WillReturnError(test.errIn)
				return db, err
			}
			defer func() {
				psqlConnect = savedPsqlConnect
				insertOutputStats = savedInsertOutputStats
			}()
			err := db.RegisterPlgnInvctn("testName")
			if err != test.expectedErr {
				t.Errorf("Errors no contains: expected: %v, got: %v", test.expectedErr, err)
			}
		})
	}

	key, err := db.GetApiKey()
	if err == nil {
		t.Fatal("Error is expected")
	}
	if key != "" {
		t.Fatal("Empty key is expected")
	}
}
