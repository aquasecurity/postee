package boltdb

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/aquasecurity/postee/v2/dbservice/dbparam"
	bolt "go.etcd.io/bbolt"
)

func TestExpiredDates(t *testing.T) {
	boltDb, _ := NewBoltDb("test_webhooks.db")
	defer boltDb.Close()
	realDueTimeBase := dbparam.DueTimeBase
	defer func() {
		os.Remove(boltDb.DbPath)
		dbparam.DueTimeBase = realDueTimeBase
	}()
	dbparam.DueTimeBase = time.Nanosecond
	tests := []struct {
		title                       string
		delay                       int
		uniqueMessageTimeoutSeconds int
		needRun                     bool
		wasStored                   bool
	}{
		{"Add initial scan", 0, 1, false, true},
		{"Add same scan again - not stored", 0, 0, true, false},
		{"Add same scan again - after delay - stored", 1, 0, true, true},
	}

	for _, test := range tests {
		t.Log(test.title)
		if test.needRun {
			time.Sleep(time.Duration(test.delay) * time.Second)
			boltDb.CheckExpiredData()
		}
		timeToExpire := time.Duration(test.uniqueMessageTimeoutSeconds) * time.Second
		expired := time.Now().UTC().Add(timeToExpire)

		wasStored, err := boltDb.MayBeStoreMessage([]byte(AlpineImageResult), AlpineImageKey, &expired)

		if err != nil {
			t.Fatal("First Add AlpineImageResult Error", err)
		}

		if wasStored != test.wasStored {
			t.Errorf("Error handling! Want wasStored: %t, got: %t", test.wasStored, wasStored)
		}
	}
}

func TestDbSizeLimit(t *testing.T) {
	boltDb, _ := NewBoltDb("test_webhooks.db")
	defer boltDb.Close()

	realSizeLimit := dbparam.DbSizeLimit
	defer func() {
		os.Remove(boltDb.DbPath)
		dbparam.DbSizeLimit = realSizeLimit
	}()

	tests := []struct {
		title   string
		limit   int
		needRun bool
		isNew   bool
	}{
		{"First scan", 0, false, true},
		{"Second scan", 0, true, false},
		{"Third scan", 1, true, true},
	}

	dbparam.DbSizeLimit = 1
	boltDb.CheckSizeLimit()

	for _, test := range tests {
		t.Log(test.title)
		dbparam.DbSizeLimit = test.limit
		if test.needRun {
			boltDb.CheckSizeLimit()
		}

		isNew, err := boltDb.MayBeStoreMessage([]byte(AlpineImageResult), AlpineImageKey, nil)
		if err != nil {
			t.Fatal("First Add AlpineImageResult Error", err)
		}

		if isNew != test.isNew {
			t.Errorf("Error handling! Want isNew: %t, rgot: %t", test.isNew, isNew)
		}
	}
}

func TestWrongBuckets(t *testing.T) {
	boltDb, _ := NewBoltDb("test_webhooks.db")
	defer boltDb.Close()
	savedDbBucketName := dbparam.DbBucketName
	savedDbBucketExpiryDates := dbparam.DbBucketExpiryDates
	defer func() {
		dbparam.DbBucketName = savedDbBucketName
		dbparam.DbBucketExpiryDates = savedDbBucketExpiryDates
		os.Remove(boltDb.DbPath)
	}()

	_, err := boltDb.MayBeStoreMessage([]byte(AlpineImageResult), AlpineImageKey, nil)
	if err != nil {
		t.Fatal(err)
	}

	dbparam.DbSizeLimit = 1
	dbparam.DbBucketName = ""
	dbparam.DbBucketExpiryDates = ""
	boltDb.CheckSizeLimit()

	dbparam.DbBucketName = "dbBucketName"
	_, err = boltDb.MayBeStoreMessage([]byte(AlpineImageResult), AlpineImageKey, nil)
	if err == nil {
		t.Error("No error for empty dbBucketExpiryDates")
	}
	dbparam.DbBucketExpiryDates = "dbBucketExpiryDates"
	dbparam.DbBucketName = ""
	_, err = boltDb.MayBeStoreMessage([]byte(AlpineImageResult), AlpineImageKey, nil)
	if err == nil {
		t.Error("No error for empty dbBucketName")
	}
}

func TestDbDelete(t *testing.T) {
	path := "test_webhooks.db"
	defer func() {
		os.Remove(path)
	}()

	db, err := bolt.Open(path, 0666, nil)
	if err != nil {
		t.Fatal("Can't open db:", path)
		return
	}
	defer db.Close()

	key := []byte("key")
	value := []byte("value")
	bucket := "b"

	key1 := []byte("key1")
	value1 := []byte("value1")
	bucket1 := "b1"

	err = dbInsert(db, bucket, key, value)
	if err != nil {
		t.Fatal("TestDbDelete dbInsert: ", err)
	}
	err = dbInsert(db, bucket1, key1, value1)
	if err != nil {
		t.Errorf("Can't insert in db: %v", err)
	}

	selectValue, err := dbSelect(db, bucket, string(key))
	if err != nil {
		t.Fatal("TestDbDelete dbInsert: ", err)
	}
	if !bytes.Equal(value, selectValue) {
		t.Errorf("bad insert/select, expected: %s, got: %s", value, selectValue)
	}

	selectValue1, err := dbSelect(db, bucket1, string(key1))
	if err != nil {
		t.Errorf("Can't delete from db: %v", err)
	}
	if !bytes.Equal(value1, selectValue1) {
		t.Errorf("bad insert/select, expected: %s, got: %s", value1, selectValue1)
	}

	err = dbDelete(db, bucket, [][]byte{key})
	if err != nil {
		t.Fatal("TestDbDelete dbInsert: ", err)
	}

	bucket = ""
	err = dbInsert(db, bucket, key, value)
	expectedError := fmt.Errorf("bucket name required")
	if errors.Is(err, expectedError) {
		t.Errorf("Unexpected error: expected %s, got %s \n", expectedError, err)
	}

	selectValue1AfterDel, err := dbSelect(db, bucket1, string(key1))
	if err != nil {
		t.Errorf("Can't delete from db: %v", err)
	}
	if !bytes.Equal(value1, selectValue1AfterDel) {
		t.Errorf("bad insert/select, expected: %s, got: %s", value1, selectValue1AfterDel)
	}

}
