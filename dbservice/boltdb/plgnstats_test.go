package boltdb

import (
	"os"
	"strconv"
	"testing"

	"github.com/aquasecurity/postee/dbservice/dbparam"
	bolt "go.etcd.io/bbolt"
)

func TestRegisterPlgnInvctn(t *testing.T) {
	path := "test_webhooks.db"
	dbBolt, _ := NewBoltDb(path)
	defer func() {
		dbBolt.Close()
		os.Remove(path)
	}()

	expectedCnt := 3
	keyToTest := "test"
	for i := 0; i < expectedCnt; i++ {
		err := dbBolt.RegisterPlgnInvctn(keyToTest)
		if err != nil {
			t.Fatal(err)
		}
	}

	r, err := getPlgnStats(dbBolt)
	if err != nil {
		t.Fatal("error while getting value of API key")
	}
	if r[keyToTest] != expectedCnt {
		t.Errorf("Persisted count doesn't match expected. Expected %d, got %d\n", r[keyToTest], expectedCnt)
	}

}

func getPlgnStats(dbBolt *BoltDb) (r map[string]int, err error) {
	r = make(map[string]int)

	err = dbBolt.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(dbparam.DbBucketOutputStats))
		if bucket == nil {
			return nil //no bucket - empty stats will be returned
		}

		c := bucket.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			cnt, err := strconv.Atoi(string(v[:]))
			if err != nil {
				return err
			}

			r[string(k[:])] = cnt
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return r, nil
}
