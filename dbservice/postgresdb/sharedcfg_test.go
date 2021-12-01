package postgresdb

import (
	"database/sql"
	"log"
	"testing"

	"github.com/jmoiron/sqlx"
	sqlxmock "github.com/zhashkevych/go-sqlxmock"
)

func TestApiKey(t *testing.T) {
	savedInitTable := initTable
	initTable = func(db *sqlx.DB, tableName string) error { return nil }
	savedInsert := insert
	insert = func(db *sqlx.DB, table, id, columnName2, value2, columnName3, value3 string) error { return nil }
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
		initTable = savedInitTable
		insert = savedInsert
		psqlConnect = savedPsqlConnect
	}()

	db.EnsureApiKey()

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
	savedInitTable := initTable
	initTable = func(db *sqlx.DB, tableName string) error { return nil }
	savedInsert := insert
	insert = func(db *sqlx.DB, table, id, columnName2, value2, columnName3, value3 string) error {
		receivedKey = value3
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
		initTable = savedInitTable
		insert = savedInsert
		psqlConnect = savedPsqlConnect
	}()

	var keys [2]string
	for i := 0; i < 2; i++ {
		db.EnsureApiKey()
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
