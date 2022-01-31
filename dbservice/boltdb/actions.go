package boltdb

import (
	"time"

	"github.com/aquasecurity/postee/dbservice/dbparam"
)

func (boltDb *BoltDb) MayBeStoreMessage(message []byte, messageKey string, expired *time.Time) (wasStored bool, err error) {
	boltDb.mu.Lock()
	defer boltDb.mu.Unlock()

	db := boltDb.db

	if err = Init(db, dbparam.DbBucketName); err != nil {
		return false, err
	}
	if err = Init(db, dbparam.DbBucketExpiryDates); err != nil {
		return false, err
	}

	currentValue, err := dbSelect(db, dbparam.DbBucketName, messageKey)
	if err != nil {
		return false, err
	}

	if currentValue != nil {
		return false, nil
	} else {
		bMessageKey := []byte(messageKey)
		err = dbInsert(db, dbparam.DbBucketName, bMessageKey, message)
		if err != nil {
			return false, err
		}
		if expired != nil {
			err = dbInsert(db, dbparam.DbBucketExpiryDates, []byte(expired.Format(dbparam.DateFmt)), bMessageKey)
			if err != nil {
				return false, err
			}
		}
		return true, nil
	}

}
