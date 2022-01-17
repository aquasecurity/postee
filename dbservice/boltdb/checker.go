package boltdb

import (
	"bytes"
	"time"

	"github.com/aquasecurity/postee/dbservice/dbparam"
	"github.com/aquasecurity/postee/log"
	bolt "go.etcd.io/bbolt"
)

func (boltDb *BoltDb) CheckSizeLimit() {
	if dbparam.DbSizeLimit == 0 {
		return
	}
	mutex.Lock()
	defer mutex.Unlock()

	db, err := bolt.Open(boltDb.DbPath, 0666, nil)
	if err != nil {
		log.Logger.Errorf("CheckSizeLimit: Can't open db: %s", boltDb.DbPath)
		return
	}
	defer db.Close()

	if err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(dbparam.DbBucketName))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		size := 0
		for k, v := c.First(); k != nil; k, v = c.Next() {
			size += len(v)
		}
		if size > dbparam.DbSizeLimit {
			return tx.DeleteBucket([]byte(dbparam.DbBucketName))
		}
		return nil
	}); err != nil {
		log.Logger.Errorf("Unable to delete bucket: %v", err)
		return
	}
}

func (boltDb *BoltDb) CheckExpiredData() {
	mutex.Lock()
	defer mutex.Unlock()

	db, err := bolt.Open(boltDb.DbPath, 0666, nil)
	if err != nil {
		log.Logger.Errorf("CheckExpiredData: Can't open db: %s", boltDb.DbPath)
		return
	}
	defer db.Close()

	expired, err := boltDb.getExpired(db)
	if err != nil {
		log.Logger.Errorf("Can't select expired data: %v", err)
		return
	}

	if err := dbDelete(db, dbparam.DbBucketName, expired); err != nil {
		log.Logger.Errorf("Can't remove expired data: %v", err)
	}
}

func (boltDb *BoltDb) getExpired(db *bolt.DB) (keys [][]byte, err error) {
	keys = [][]byte{}
	ttlKeys := [][]byte{}

	if err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(dbparam.DbBucketExpiryDates))
		if b == nil {
			return nil
		}
		c := b.Cursor()

		max := []byte(time.Now().UTC().Format(dbparam.DateFmt)) //remove expired records
		for k, v := c.First(); k != nil && bytes.Compare(k, max) <= 0; k, v = c.Next() {
			keys = append(keys, v)
			ttlKeys = append(ttlKeys, k)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	if err = dbDelete(db, dbparam.DbBucketExpiryDates, ttlKeys); err != nil {
		return nil, err
	}

	return
}
