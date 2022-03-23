package dbservice

import (
	"github.com/stretchr/testify/assert"
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

func TestCheckSizeLimit(t *testing.T) {
	dbPathReal := DbPath
	realSizeLimit := DbSizeLimit
	defer func() {
		DbPath = dbPathReal
		DbSizeLimit = realSizeLimit
	}()

	DbPath = "test_webhooks.db"

	tests := []struct {
		name        string
		dbSizeLimit int
		wasCleared  bool
	}{
		{
			name:        "DB has been cleared",
			dbSizeLimit: 1,
			wasCleared:  true,
		},
		{
			name:       "DB not cleared",
			wasCleared: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			DbSizeLimit = test.dbSizeLimit

			db, err := bolt.Open(DbPath, 0666, nil)
			if err != nil {
				t.Fatal("Can't open db:", DbPath)
			}
			defer func() {
				os.Remove(DbPath)
				db.Close()
			}()

			err = dbInsert(db, dbBucketName, []byte("sha256:12345"), []byte("input_struct"))
			if err != nil {
				t.Fatal("TestDbDelete dbInsert: ", err)
			}

			err = dbInsert(db, dbBucketExpiryDates, []byte("2222-02-22T04:37:25.251356543Z"), []byte("sha256:12345"))
			if err != nil {
				t.Fatal("TestDbDelete dbInsert: ", err)
			}

			err = db.Close() // CheckSizeLimit() will open DB. We must close DB before doing this.
			if err != nil {
				t.Errorf("unable close DB: %v", err)
			}

			CheckSizeLimit()

			existDbBucketName, err := dbBucketExists(db, dbBucketName)
			if err != nil {
				t.Errorf("Unable to check if bucket exists: %v", err)
			}

			existDbBucketExpiryDates, err := dbBucketExists(db, dbBucketExpiryDates)
			if err != nil {
				t.Errorf("Unable to check if bucket exists: %v", err)
			}

			if test.wasCleared {
				assert.False(t, existDbBucketName)
				assert.False(t, existDbBucketExpiryDates)
			} else {
				assert.True(t, existDbBucketName)
				assert.True(t, existDbBucketExpiryDates)
			}

		})
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

	err = db.Close()
	if err != nil {
		t.Errorf("Unable close DB: %v", err)
	}

	exist, err := dbBucketExists(db, bucket)
	if err != nil {
		t.Errorf("Unable to check if bucket exists: %v", err)
	}

	if !exist {
		t.Errorf("bucket hasn't been removed ")
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
	}
	db.Close()
	DbSizeLimit = 1
	CheckSizeLimit()
	CheckExpiredData()
}

func dbBucketExists(db *bolt.DB, bucket string) (bool, error) {
	bucketExist := false

	db, err := bolt.Open(DbPath, 0666, nil)
	if err != nil {
		return false, err
	}
	defer func() {
		db.Close()
	}()

	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b != nil {
			bucketExist = true
			return nil
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return bucketExist, nil
}
