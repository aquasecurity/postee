package dbservice

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/postee/data"
	bolt "go.etcd.io/bbolt"
	"time"
)

func HandleCurrentInfo(scanInfo *data.ScanImageInfo) (prev []byte, isNew bool, err error) {
	mutex.Lock()
	defer mutex.Unlock()

	currentId := scanInfo.GetUniqueId()
	var prevId string
	if scanInfo.PreviousDigest != "" {
		prevId = data.BuildUniqueId(scanInfo.PreviousDigest, scanInfo.Image, scanInfo.Registry)
	}

	db, err := bolt.Open(DbPath, 0666, nil)
	if err != nil {
		return nil, false, err
	}
	defer db.Close()

	if err = Init(db, dbBucketName); err != nil {
		return
	}
	if err = Init(db, dbBucketExpiryDates); err != nil {
		return
	}

	currentValue, err := dbSelect(db, dbBucketName, currentId)
	if err != nil {
		return
	}

	if currentValue != nil {
		savedScan := new(data.ScanImageInfo)
		err = json.Unmarshal(currentValue, savedScan)
		if err != nil {
			fmt.Println(err)
			return
		}

		if savedScan.Critical == scanInfo.Critical &&
			savedScan.High == scanInfo.High &&
			savedScan.Medium == scanInfo.Medium &&
			savedScan.Low == scanInfo.Low &&
			savedScan.Negligible == scanInfo.Negligible &&
			savedScan.Malware == scanInfo.Malware {
			return nil, false, nil
		}
	}

	currentBytes, _ := json.Marshal(scanInfo)
	bCurrentId := []byte(currentId)
	err = dbInsert(db, dbBucketName, bCurrentId, currentBytes)
	if err != nil {
		return nil, false, err
	}
	isNew = true

	err = dbInsert(db, dbBucketExpiryDates, []byte(time.Now().UTC().Format(time.RFC3339Nano)), bCurrentId)
	if err != nil {
		return
	}

	if prevId != "" && prevId != currentId {
		prev, _ = dbSelect(db, dbBucketName, prevId)
	}
	return
}
