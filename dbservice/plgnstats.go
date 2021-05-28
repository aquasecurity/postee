package dbservice

import (
	"strconv"

	bolt "go.etcd.io/bbolt"
)

func RegisterPlgnInvctn(name string) error {
	mutex.Lock()
	defer mutex.Unlock()

	db, err := bolt.Open(DbPath, 0666, nil)
	if err != nil {
		return err
	}
	defer db.Close()

	err = db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(DbBucketOutputScanStats))
		if bucket == nil {
			bucket, err = tx.CreateBucket([]byte(DbBucketOutputScanStats))

			if err != nil {
				return err
			}
			err = bucket.Put([]byte(name), []byte("1"))
			return err
		}
		v := bucket.Get([]byte(name))
		i, err := strconv.Atoi(string(v[:]))

		i++
		nwv := strconv.Itoa(i)

		err = bucket.Put([]byte(name), []byte(nwv))
		return err
	})

	return err
}
