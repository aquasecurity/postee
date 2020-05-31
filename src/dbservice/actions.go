package dbservice

import (
	"data"
	"encoding/json"
	"fmt"
	bolt "go.etcd.io/bbolt"
)

func HandleCurrentInfo( scanInfo *data.ScanImageInfo) (prev []byte, isNew bool, err error) {
	mutex.Lock()
	defer mutex.Unlock()

	currentId := scanInfo.GetUniqueId()
	var prevId string
	if scanInfo.PreviousDigest != "" {
		prevId = data.BuildUniqueId(scanInfo.PreviousDigest, scanInfo.Image, scanInfo.Registry)
	}

	db, err := bolt.Open( DbPath, 0666, nil )
	if err != nil {
		return nil, false, err
	}
	defer db.Close()

	err = Init(db, dbBucketName)
	if err != nil {
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
	err = dbInsert(db, dbBucketName, []byte(currentId), currentBytes)
	if err != nil {
		return nil, false, err
	}
	isNew = true

	if prevId != "" && prevId != currentId {
		prev,_ = dbSelect(db, dbBucketName, prevId)
	}
	return
}


