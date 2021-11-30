package boltdb

import (
	"os"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestExpiredDates(t *testing.T) {
	boltDb := NewBoltDb()
	dbPathReal := boltDb.DbPath
	realDueTimeBase := dueTimeBase
	defer func() {
		os.Remove(boltDb.DbPath)
		boltDb.DbPath = dbPathReal
		dueTimeBase = realDueTimeBase
	}()
	dueTimeBase = time.Nanosecond
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
	realSizeLimit := DbSizeLimit
	defer func() {
		os.Remove(boltDb.DbPath)
		boltDb.DbPath = dbPathReal
		DbSizeLimit = realSizeLimit
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

	DbSizeLimit = 1
	boltDb.CheckSizeLimit()

	for _, test := range tests {
		t.Log(test.title)
		DbSizeLimit = test.limit
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
	savedDbBucketName := dbBucketName
	savedDbBucketExpiryDates := dbBucketExpiryDates
	dbPathReal := boltDb.DbPath
	defer func() {
		dbBucketName = savedDbBucketName
		dbBucketExpiryDates = savedDbBucketExpiryDates
		os.Remove(boltDb.DbPath)
		boltDb.DbPath = dbPathReal
	}()
	boltDb.DbPath = "test_webhooks.db"

	_, err := boltDb.MayBeStoreMessage([]byte(AlpineImageResult), AlpineImageKey, nil)
	if err != nil {
		t.Fatal(err)
	}

	DbSizeLimit = 1
	dbBucketName = ""
	dbBucketExpiryDates = ""
	boltDb.CheckSizeLimit()

	dbBucketName = "dbBucketName"
	_, err = boltDb.MayBeStoreMessage([]byte(AlpineImageResult), AlpineImageKey, nil)
	if err == nil {
		t.Error("No error for empty dbBucketExpiryDates")
	}
	dbBucketExpiryDates = "dbBucketExpiryDates"
	dbBucketName = ""
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

	dbInsert(db, bucket, key, value)
	dbDelete(db, bucket, [][]byte{key})
	dbDelete(db, bucket, [][]byte{key})

	bucket = ""
	dbInsert(db, bucket, key, value)
}

func TestWithoutAccessToDb(t *testing.T) {
	boltDb := NewBoltDb()
	dbPathReal := boltDb.DbPath
	defer func() {
		os.Remove(boltDb.DbPath)
		boltDb.DbPath = dbPathReal
	}()
	boltDb.DbPath = "test_webhooks.db"
	db, err := bolt.Open(boltDb.DbPath, 0220, nil)
	if err != nil {
		t.Fatal("Can't open db:", boltDb.DbPath)
		return
	}
	db.Close()
	DbSizeLimit = 1
	boltDb.CheckSizeLimit()
	boltDb.CheckExpiredData()
}
