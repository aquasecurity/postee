package boltdb

import (
	"errors"

	"github.com/aquasecurity/postee/dbservice/dbparam"
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

	err = Init(db, dbparam.DbBucketOutputStats)
	if err != nil {
		return err
	}

	newApiKey, err := dbparam.GenerateApiKey(32)
	if err != nil {
		return err
	}

	err = dbInsert(db, dbparam.DbBucketSharedConfig, []byte(apiKeyName), []byte(newApiKey))

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
		bucket := tx.Bucket([]byte(dbparam.DbBucketSharedConfig))
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
