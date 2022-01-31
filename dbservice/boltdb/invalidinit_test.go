package boltdb

import (
	"errors"
	"os"
	"testing"

	"go.etcd.io/bbolt"
)

var tests = []struct {
	caseDesc        string
	errPrvdr        func(db *BoltDb) error
	initIsNotCalled bool
}{
	{
		caseDesc: "EnsureApiKey",
		errPrvdr: func(dbTest *BoltDb) error {
			return dbTest.EnsureApiKey()
		},
	},
	{
		caseDesc: "GetApiKey",
		errPrvdr: func(dbTest *BoltDb) error {
			_, err := dbTest.GetApiKey()
			return err
		},
		initIsNotCalled: true,
	},
	{
		caseDesc: "RegisterPlgnInvctn",
		errPrvdr: func(dbTest *BoltDb) error {
			return dbTest.RegisterPlgnInvctn("some-key")
		},
	},
	{
		caseDesc: "MayBeStoreMessage",
		errPrvdr: func(dbTest *BoltDb) error {
			_, err := dbTest.MayBeStoreMessage(nil, "a-b-c", nil)
			return err
		},
	},
	{
		caseDesc: "AggregateScans",
		errPrvdr: func(dbTest *BoltDb) error {
			_, err := dbTest.AggregateScans("", map[string]string{}, 1, false)
			return err
		},
	},
}

func TestInvalidDbPath(t *testing.T) {
	path := "/tmp"
	_, err := NewBoltDb(path)
	if err == nil {
		t.Errorf("Error is expected when bad path '%s' passed\n", path)
	}

}

func TestBucketInitialization(t *testing.T) {
	path := "test_webhooks.db"
	db, _ := NewBoltDb(path)
	defer db.Close()

	savedInit := Init
	defer func() {
		os.Remove(path)
		Init = savedInit
	}()

	expectedError := errors.New("weird error")
	Init = func(db *bbolt.DB, bucket string) error {
		return expectedError
	}
	for _, test := range tests {
		if test.initIsNotCalled {
			continue
		}
		err := test.errPrvdr(db)
		if !errors.Is(err, expectedError) {
			t.Errorf("Unexpected error for %s call, expected %v, got %v", test.caseDesc, expectedError, err)
		}

	}
}
