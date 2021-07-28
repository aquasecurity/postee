package dbservice

import bolt "go.etcd.io/bbolt"

var dbInsert = func(db *bolt.DB, bucket string, key, value []byte) error {
	err := db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucket))
		if err != nil {
			return err
		}
		return b.Put(key, value)
	})
	return err
}
