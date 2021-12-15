package boltdb

import (
	"errors"
	"os"
	"testing"

	"go.etcd.io/bbolt"
)

var db = NewBoltDb()

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

func TestInvalidDbPath(t *testing.T) {
	dbPathReal := db.DbPath
	defer func() {
		os.Remove(db.DbPath)
		db.DbPath = dbPathReal
	}()
	db.DbPath = "/tmp"

	for _, test := range tests {
		err := test.errPrvdr()
		if err == nil {
			t.Errorf("Error is expected when %s is called\n", test.caseDesc)
		}

	}
}
func TestBucketInitialization(t *testing.T) {
	savedInit := Init
	dbPathReal := db.DbPath
	defer func() {
		os.Remove(db.DbPath)
		Init = savedInit
		db.DbPath = dbPathReal
	}()
	db.DbPath = "test_webhooks.db"
	expectedError := errors.New("weird error")
	Init = func(db *bbolt.DB, bucket string) error {
		return expectedError
	}
	for _, test := range tests {
		if test.initIsNotCalled {
			continue
		}
		err := test.errPrvdr()
		if !errors.Is(err, expectedError) {
			t.Errorf("Unexpected error for %s call, expected %v, got %v", test.caseDesc, expectedError, err)
		}

	}
}
