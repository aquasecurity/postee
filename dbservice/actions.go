package dbservice

import (
	"time"

	bolt "go.etcd.io/bbolt"
)

func MayBeStoreMessage(message []byte, messageKey string) (wasStored bool, err error) {
	mutex.Lock()
	defer mutex.Unlock()

	db, err := bolt.Open(DbPath, 0666, nil)
	if err != nil {
		return false, err
	}
	defer db.Close()

	if err = Init(db, dbBucketName); err != nil {
		return false, err
	}
	if err = Init(db, dbBucketExpiryDates); err != nil {
		return false, err
	}

	currentValue, err := dbSelect(db, dbBucketName, messageKey)
	if err != nil {
		return false, err
	}

	if currentValue != nil {
		return false, nil
	} else {
		bMessageKey := []byte(messageKey)
		err = dbInsert(db, dbBucketName, bMessageKey, message)
		if err != nil {
			return false, err
		}
		err = dbInsert(db, dbBucketExpiryDates, []byte(time.Now().UTC().Format(time.RFC3339Nano)), bMessageKey)
		if err != nil {
			return false, err
		}
		return true, nil
	}

}
