package postgresdb

import (
	"errors"
	"log"
	"testing"

	"github.com/jmoiron/sqlx"
	sqlxmock "github.com/zhashkevych/go-sqlxmock"
)

var tests = []struct {
	caseDesc        string
	errPrvdr        func() error
	initIsNotCalled bool
}{
	{
		caseDesc: "EnsureApiKey",
		errPrvdr: func() error {
			return db.EnsureApiKey()
		},
	},
	{
		caseDesc: "GetApiKey",
		errPrvdr: func() error {
			_, err := db.GetApiKey()
			return err
		},
		initIsNotCalled: true,
	},
	{
		caseDesc: "RegisterPlgnInvctn",
		errPrvdr: func() error {
			return db.RegisterPlgnInvctn("some-key")
		},
	},
	{
		caseDesc: "MayBeStoreMessage",
		errPrvdr: func() error {
			_, err := db.MayBeStoreMessage(nil, "a-b-c", nil)
			return err
		},
	},
	{
		caseDesc: "AggregateScans",
		errPrvdr: func() error {
			_, err := db.AggregateScans("", map[string]string{}, 1, false)
			return err
		},
	},
}

func TestTableInitialization(t *testing.T) {
	expectedError := errors.New("weird error")
	savedInitTable := initTable
	savedPsqlConnect := psqlConnect
	initTable = func(db *sqlx.DB, tableName string) error { return expectedError }
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		db, _, err := sqlxmock.Newx()
		if err != nil {
			log.Println("failed to open sqlmock database:", err)
		}
		return db, err
	}
	defer func() {
		initTable = savedInitTable
		psqlConnect = savedPsqlConnect
	}()

	for _, test := range tests {
		if test.initIsNotCalled {
			continue
		}
		err := test.errPrvdr()
		if err != expectedError {
			t.Errorf("Unexpected error for %s call, expected %v, got %v", test.caseDesc, expectedError, err)
		}

	}
}
