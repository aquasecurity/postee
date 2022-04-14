package boltdb

import (
	"bytes"
	"time"

	"github.com/aquasecurity/postee/v2/dbservice/dbparam"
	"github.com/aquasecurity/postee/v2/log"
	bolt "go.etcd.io/bbolt"
)

const mb = 1024 * 1024

func (boltDb *BoltDb) CheckSizeLimit() {
	if dbparam.DbSizeLimit == 0 {
		return
	}
	boltDb.mu.Lock()
	defer boltDb.mu.Unlock()

	db := boltDb.db

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

		if size > dbparam.DbSizeLimit*mb {
			return tx.DeleteBucket([]byte(dbparam.DbBucketName))
		}
		return nil
	}); err != nil {
		log.Logger.Debugf("Unable to delete bucket: %v", err)
		return
	}
}

func (boltDb *BoltDb) CheckExpiredData() {
	boltDb.mu.Lock()
	defer boltDb.mu.Unlock()

	db := boltDb.db

	expired, err := boltDb.getExpired(db)
	if err != nil {
		log.Logger.Debugf("Can't select expired data: %v", err)
		return
	}

	if err := dbDelete(db, dbparam.DbBucketName, expired); err != nil {
		log.Logger.Debugf("Can't remove expired data: %v", err)
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
