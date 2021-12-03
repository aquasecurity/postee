package postgresdb

import (
	"log"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	sqlxmock "github.com/zhashkevych/go-sqlxmock"
)

func TestStoreMessage(t *testing.T) {
	currentValueStoreMessage := ""
	time := time.Now()

	savedInitTable := initTable
	initTable = func(db *sqlx.DB, tableName string) error { return nil }
	savedinsertInTableName := insertInTableName
	insertInTableName = func(db *sqlx.DB, id, date, messageKey, messageValue string) error {
		currentValueStoreMessage = messageValue
		return nil
	}
	savedPsqlConnect := psqlConnect
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		db, mock, err := sqlxmock.Newx()
		if err != nil {
			log.Println("failed to open sqlmock database:", err)
		}
		rows := sqlxmock.NewRows([]string{"messagevalue"}).AddRow(currentValueStoreMessage)
		mock.ExpectQuery("SELECT").WillReturnRows(rows)
		return db, err
	}
	defer func() {
		initTable = savedInitTable
		insertInTableName = savedinsertInTableName
		psqlConnect = savedPsqlConnect
	}()

	var tests = []struct {
		input *string
	}{
		{&AlpineImageResult},
	}

	for _, test := range tests {

		// Handling of first scan
		isNew, err := db.MayBeStoreMessage([]byte(*test.input), AlpineImageKey, &time)
		if err != nil {
			t.Errorf("Error: %s\n", err)
		}
		if !isNew {
			t.Errorf("A first scan was found!\n")
		}

		// Handling of second scan with the same data
		isNew, err = db.MayBeStoreMessage([]byte(*test.input), AlpineImageKey, nil)
		if err != nil {
			t.Errorf("Error: %s\n", err)
		}
		if isNew {
			t.Errorf("A old scan wasn't found!\n")
		}
	}

}
