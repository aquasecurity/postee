package postgresdb

import (
	"database/sql"
	"log"
	"testing"

	"github.com/jmoiron/sqlx"
	sqlxmock "github.com/zhashkevych/go-sqlxmock"
)

func TestApiKey(t *testing.T) {
	savedInsertInTableSharedConfig := insertInTableSharedConfig
	insertInTableSharedConfig = func(db *sqlx.DB, tenantName, apikeyname, value string) error { return nil }
	savedPsqlConnect := psqlConnect
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		db, mock, err := sqlxmock.Newx()
		if err != nil {
			log.Println("failed to open sqlmock database:", err)
		}
		rows := sqlxmock.NewRows([]string{"value"}).AddRow("key")
		mock.ExpectQuery("SELECT").WillReturnRows(rows)
		return db, err
	}
	defer func() {
		insertInTableSharedConfig = savedInsertInTableSharedConfig
		psqlConnect = savedPsqlConnect
	}()

	if err := db.EnsureApiKey(); err != nil {
		t.Errorf("Unexpected EnsureApiKey error: %v", err)
	}

	key, err := db.GetApiKey()
	if err != nil {
		t.Fatal("error while getting value of API key")
	}
	if key == "" {
		t.Fatal("empty key received")
	}
}

func TestApiKeyWithoutInit(t *testing.T) {
	savedPsqlConnect := psqlConnect
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		db, mock, err := sqlxmock.Newx()
		if err != nil {
			log.Println("failed to open sqlmock database:", err)
		}
		mock.ExpectQuery("SELECT").WillReturnError(sql.ErrNoRows)
		return db, err
	}
	defer func() {
		psqlConnect = savedPsqlConnect
	}()
	key, err := db.GetApiKey()
	if err == nil {
		t.Fatal("Error is expected")
	}
	if key != "" {
		t.Fatal("Empty key is expected")
	}
}

func TestApiKeyRenewal(t *testing.T) {
	receivedKey := ""
	savedInsertInTableSharedConfig := insertInTableSharedConfig
	insertInTableSharedConfig = func(db *sqlx.DB, tenantName, apikeyname, value string) error {
		receivedKey = value
		return nil
	}
	savedPsqlConnect := psqlConnect
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		db, mock, err := sqlxmock.Newx()
		if err != nil {
			log.Println("failed to open sqlmock database:", err)
		}
		rows := sqlxmock.NewRows([]string{"value"}).AddRow(receivedKey)
		mock.ExpectQuery("SELECT").WillReturnRows(rows)
		return db, err
	}
	defer func() {
		insertInTableSharedConfig = savedInsertInTableSharedConfig
		psqlConnect = savedPsqlConnect
	}()

	var keys [2]string
	for i := 0; i < 2; i++ {
		if err := db.EnsureApiKey(); err != nil {
			t.Errorf("Unexpected EnsureApiKey error: %v", err)
		}
		key, err := db.GetApiKey()
		if err != nil {
			t.Fatal("error while getting value of API key")
		}
		if key == "" {
			t.Fatal("empty key received")
		}
		keys[i] = key
	}
	if keys[0] == keys[1] {
		t.Errorf("Key is not updated. (before: %s and after update: %s)", keys[0], keys[1])
	}
}
