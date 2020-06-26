package dbservice

import (
	bolt "go.etcd.io/bbolt"
	"os"
	"testing"
	"time"
)
func TestExpiredDates(t *testing.T) {
	dbPathReal := DbPath
	realDueDate := DbDueDate
	realDueTimeBase := dueTimeBase
	defer func() {
		os.Remove(DbPath)
		DbPath = dbPathReal
		DbDueDate = realDueDate
		dueTimeBase = realDueTimeBase
	}()
	dueTimeBase = time.Nanosecond
	DbPath = "test_webhooks.db"
	tests := []struct {
		title string
		limit int
		needRun bool
		isNew bool
	}{
		{ "First scan", 0, false, true },
		{ "Second scan", 0, true, false },
		{ "Third scan", 1, true, true },
	}

	DbDueDate = 1
	CheckExpiredData()

	for _, test := range tests {
		t.Log(test.title)
		DbDueDate = test.limit
		if test.needRun {
			CheckExpiredData()
		}

		_, isNew, err := HandleCurrentInfo(&AlpineImageResult)
		if err != nil {
			t.Fatal("First Add AlpineImageResult Error", err)
		}

		if isNew != test.isNew {
			t.Errorf("Error handling! Want isNew: %t, rgot: %t", test.isNew, isNew)
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
		title string
		limit int
		needRun bool
		isNew bool
	}{
		{ "First scan", 0, false, true },
		{ "Second scan", 0, true, false },
		{ "Third scan", 1, true, true },
	}

	DbSizeLimit = 1
	CheckSizeLimit()

	for _, test := range tests {
		t.Log(test.title)
		DbSizeLimit = test.limit
		if test.needRun {
			CheckSizeLimit()
		}

		_, isNew, err := HandleCurrentInfo(&AlpineImageResult)
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

	_, _, err := HandleCurrentInfo(&AlpineImageResult)
	if err != nil {
		t.Fatal(err)
	}

	DbSizeLimit = 1
	dbBucketName = ""
	dbBucketExpiryDates = ""
	CheckSizeLimit()
}

func TestDbDelete(t *testing.T) {
	dbPathReal := DbPath
	defer func() {
		os.Remove(DbPath)
		DbPath = dbPathReal
	}()
	DbPath = "test_webhooks.db"

	db, err := bolt.Open( DbPath, 0666, nil )
	if err != nil {
		t.Fatal("Can't open db:", DbPath)
		return
	}
	defer db.Close()

	key := []byte("key")
	value := []byte("value")
	bucket := "b"

	dbInsert(db, bucket, key, value)
	dbDelete(db, bucket, [][]byte{ key })
	dbDelete(db, bucket, [][]byte{ key })

	bucket = ""
	dbInsert(db, bucket, key, value)
}