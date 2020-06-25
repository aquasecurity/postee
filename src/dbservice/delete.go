package dbservice

import bolt "go.etcd.io/bbolt"

func dbDelete (db *bolt.DB, bucket string, keys [][]byte) error {
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		for _, key := range keys {
			if err := b.Delete(key); err != nil {return err}
		}
		return nil
	})
}
