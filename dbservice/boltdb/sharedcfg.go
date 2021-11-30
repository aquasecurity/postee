package boltdb

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"

	bolt "go.etcd.io/bbolt"
)

const (
	apiKeyName = "POSTEE_API_KEY"
)

func (boltDb *BoltDb) EnsureApiKey() error {
	mutex.Lock()
	defer mutex.Unlock()

	db, err := bolt.Open(boltDb.DbPath, 0666, nil)
	if err != nil {
		return err
	}
	defer db.Close()

	err = Init(db, dbBucketOutputStats)
	if err != nil {
		return err
	}

	newApiKey, err := generateApiKey(32)
	if err != nil {
		return err
	}

	err = dbInsert(db, dbBucketSharedConfig, []byte(apiKeyName), []byte(newApiKey))

	return err
}
func (boltDb *BoltDb) GetApiKey() (string, error) {
	var apiKey string = ""
	db, err := bolt.Open(boltDb.DbPath, 0444, nil) //should be enough
	if err != nil {
		return "", err
	}
	defer db.Close()
	err = db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(dbBucketSharedConfig))
		if bucket == nil {
			return errors.New("no bucket") //no bucket
		}

		bytes := bucket.Get([]byte(apiKeyName))

		apiKey = string(bytes[:])
		return nil
	})
	if err != nil {
		return "", err
	}

	return apiKey, nil

}
func generateApiKey(length int) (string, error) {
	k := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return "", err
	}
	return hex.EncodeToString(k), nil
}
