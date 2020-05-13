package dbservice

import "go.etcd.io/bbolt"

func Init(db *bbolt.DB) error {
	return db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(BucketName))
		if err != nil {
			return err
		}
		return nil
	})
}