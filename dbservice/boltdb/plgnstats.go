package boltdb

import (
	"strconv"

	"github.com/aquasecurity/postee/dbservice/dbparam"
	bolt "go.etcd.io/bbolt"
)

func (boltDb *BoltDb) RegisterPlgnInvctn(name string) error {
	boltDb.mu.Lock()
	defer boltDb.mu.Unlock()

	db := boltDb.db

	err := Init(db, dbparam.DbBucketOutputStats)
	if err != nil {
		return err
	}

	err = db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(dbparam.DbBucketOutputStats))
		var i int
		v := bucket.Get([]byte(name))

		if v == nil {
			i = 0
		} else {
			i, err = strconv.Atoi(string(v[:]))
		}

		i++
		nwv := strconv.Itoa(i)

		err = bucket.Put([]byte(name), []byte(nwv))
		return err
	})

	return err
}
