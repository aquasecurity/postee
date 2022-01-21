package dbservice

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestExpiredDates(t *testing.T) {
	dbPathReal := DbPath
	realDueTimeBase := dueTimeBase
	defer func() {
		os.Remove(DbPath)
		DbPath = dbPathReal
		dueTimeBase = realDueTimeBase
	}()
	dueTimeBase = time.Nanosecond
	DbPath = "test_webhooks.db"
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
			CheckExpiredData()
		}
		timeToExpire := time.Duration(test.uniqueMessageTimeoutSeconds) * time.Second
		expired := time.Now().UTC().Add(timeToExpire)

		wasStored, err := MayBeStoreMessage([]byte(AlpineImageResult), AlpineImageKey, &expired)

		if err != nil {
			t.Fatal("First Add AlpineImageResult Error", err)
		}

		if wasStored != test.wasStored {
			t.Errorf("Error handling! Want wasStored: %t, got: %t", test.wasStored, wasStored)
		}
	}
}

func TestDbSizeLimnit(t *testing.T) {
	dbPathReal := DbPath
	realSizeLimit := DbSizeLimit
	defer func() {
		os.Remove(DbPath)
		DbPath = dbPathReal
		DbSizeLimit = realSizeLimit
	}()
	DbPath = "test_webhooks.db"

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

	DbSizeLimit = 1
	CheckSizeLimit()

	for _, test := range tests {
		t.Log(test.title)
		DbSizeLimit = test.limit
		if test.needRun {
			CheckSizeLimit()
		}

		isNew, err := MayBeStoreMessage([]byte(AlpineImageResult), AlpineImageKey, nil)
		if err != nil {
			t.Fatal("First Add AlpineImageResult Error", err)
		}

		if isNew != test.isNew {
			t.Errorf("Error handling! Want isNew: %t, rgot: %t", test.isNew, isNew)
		}
	}
}

func TestWrongBuckets(t *testing.T) {
	savedDbBucketName := dbBucketName
	savedDbBucketExpiryDates := dbBucketExpiryDates
	dbPathReal := DbPath
	defer func() {
		dbBucketName = savedDbBucketName
		dbBucketExpiryDates = savedDbBucketExpiryDates
		os.Remove(DbPath)
		DbPath = dbPathReal
	}()
	DbPath = "test_webhooks.db"

	_, err := MayBeStoreMessage([]byte(AlpineImageResult), AlpineImageKey, nil)
	if err != nil {
		t.Fatal(err)
	}

	DbSizeLimit = 1
	dbBucketName = ""
	dbBucketExpiryDates = ""
	CheckSizeLimit()

	dbBucketName = "dbBucketName"
	_, err = MayBeStoreMessage([]byte(AlpineImageResult), AlpineImageKey, nil)
	if err == nil {
		t.Error("No error for empty dbBucketExpiryDates")
	}
	dbBucketExpiryDates = "dbBucketExpiryDates"
	dbBucketName = ""
	_, err = MayBeStoreMessage([]byte(AlpineImageResult), AlpineImageKey, nil)
	if err == nil {
		t.Error("No error for empty dbBucketName")
	}
}

func TestDbDelete(t *testing.T) {
	dbPathReal := DbPath
	defer func() {
		os.Remove(DbPath)
		DbPath = dbPathReal
	}()
	DbPath = "test_webhooks.db"

	db, err := bolt.Open(DbPath, 0666, nil)
	if err != nil {
		t.Fatal("Can't open db:", DbPath)
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
	dbPathReal := DbPath
	defer func() {
		os.Remove(DbPath)
		DbPath = dbPathReal
	}()
	DbPath = "test_webhooks.db"
	db, err := bolt.Open(DbPath, 0220, nil)
	if err != nil {
		t.Fatal("Can't open db:", DbPath)
		return
	}
	db.Close()
	DbSizeLimit = 1
	CheckSizeLimit()
	CheckExpiredData()
}
