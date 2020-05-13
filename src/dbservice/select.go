package dbservice

import bolt "go.etcd.io/bbolt"

func dbSelect(db *bolt.DB,key string) (result []byte, err error) {
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BucketName))
		result = b.Get([]byte(key))
		return nil
	})
	return
}