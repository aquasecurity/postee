package dbservice

import "go.etcd.io/bbolt"

func Init(db *bbolt.DB, bucket string) error {
	return db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucket))
		return err
	})
}