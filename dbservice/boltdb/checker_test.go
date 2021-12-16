package boltdb

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/aquasecurity/postee/dbservice/dbparam"
	bolt "go.etcd.io/bbolt"
)

func TestExpiredDates(t *testing.T) {
	boltDb := NewBoltDb()
	dbPathReal := boltDb.DbPath
	realDueTimeBase := dbparam.DueTimeBase
	defer func() {
		os.Remove(boltDb.DbPath)
		boltDb.DbPath = dbPathReal
		dbparam.DueTimeBase = realDueTimeBase
	}()
	dbparam.DueTimeBase = time.Nanosecond
	boltDb.DbPath = "test_webhooks.db"
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

func TestDbSizeLimnit(t *testing.T) {
	boltDb := NewBoltDb()
	dbPathReal := boltDb.DbPath
	realSizeLimit := dbparam.DbSizeLimit
	defer func() {
		os.Remove(boltDb.DbPath)
		boltDb.DbPath = dbPathReal
		dbparam.DbSizeLimit = realSizeLimit
	}()
	boltDb.DbPath = "test_webhooks.db"

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
	boltDb := NewBoltDb()
	savedDbBucketName := dbparam.DbBucketName
	savedDbBucketExpiryDates := dbparam.DbBucketExpiryDates
	dbPathReal := boltDb.DbPath
	defer func() {
		dbparam.DbBucketName = savedDbBucketName
		dbparam.DbBucketExpiryDates = savedDbBucketExpiryDates
		os.Remove(boltDb.DbPath)
		boltDb.DbPath = dbPathReal
	}()
	boltDb.DbPath = "test_webhooks.db"

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
	boltDb := NewBoltDb()
	dbPathReal := boltDb.DbPath
	defer func() {
		os.Remove(boltDb.DbPath)
		boltDb.DbPath = dbPathReal
	}()
	boltDb.DbPath = "test_webhooks.db"

	db, err := bolt.Open(boltDb.DbPath, 0666, nil)
	if err != nil {
		t.Fatal("Can't open db:", boltDb.DbPath)
		return
	}
	defer db.Close()

	key := []byte("key")
	value := []byte("value")
	bucket := "b"

	err = dbInsert(db, bucket, key, value)
	if err != nil {
		t.Fatal("TestDbDelete dbInsert: ", err)
	}
	err = dbDelete(db, bucket, [][]byte{key})
	if err != nil {
		t.Fatal("TestDbDelete dbInsert: ", err)
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
}

func TestWithoutAccessToDb(t *testing.T) {
	boltDb := NewBoltDb()
	dbPathReal := boltDb.DbPath
	defer func() {
		err := os.Remove(boltDb.DbPath)
		if err != nil {
			t.Errorf("Can't remove db: %v", err)
		}
		boltDb.DbPath = dbPathReal
	}()
	boltDb.DbPath = "test_webhooks.db"
	db, err := bolt.Open(boltDb.DbPath, 0220, nil)
	if err != nil {
		t.Fatal("Can't open db:", boltDb.DbPath)
		return
	}
	db.Close()
	dbparam.DbSizeLimit = 1
	boltDb.CheckSizeLimit()
	boltDb.CheckExpiredData()
}
