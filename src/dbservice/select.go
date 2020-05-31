package dbservice

import (
	bolt "go.etcd.io/bbolt"
)

func dbSelect(db *bolt.DB, bucket, key string) (result []byte, err error) {
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		r := b.Get([]byte(key))
		if r != nil {
			result = make([]byte, len(r))
			copy(result, r)
		}
		return nil
	})
	return
}