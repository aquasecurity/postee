package postgresdb

import (
	"log"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	sqlxmock "github.com/zhashkevych/go-sqlxmock"
)

func TestStoreMessage(t *testing.T) {
	currentValueStoreMessage := []byte{}

	savedinsertInTableName := insertInTableName
	insertInTableName = func(db *sqlx.DB, id, messageKey string, messageValue []byte, date *time.Time) error {
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
		insertInTableName = savedinsertInTableName
		psqlConnect = savedPsqlConnect
	}()

	var tests = []struct {
		input *string
		t     *time.Time
	}{
		{&AlpineImageResult, nil},
		{&AlpineImageResult, &time.Time{}},
	}

	for _, test := range tests {

		// Handling of first scan
		isNew, err := db.MayBeStoreMessage([]byte(*test.input), AlpineImageKey, test.t)
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
		currentValueStoreMessage = []byte{}
	}

}
