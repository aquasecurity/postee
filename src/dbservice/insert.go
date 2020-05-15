package dbservice

import bolt "go.etcd.io/bbolt"

func dbInsert(db *bolt.DB, key, value []byte) error {
	err := db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(BucketName))
		if err != nil {
			return err
		}
		return b.Put(key, value)
	})
	return err
}

