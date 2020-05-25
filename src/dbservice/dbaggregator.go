package dbservice

import (
	"encoding/json"
	bolt "go.etcd.io/bbolt"
)

func AggregateScans(plugin string, currentScan map[string]string, scansPerTicket int) ( []map[string]string, error) {
	mutex.Lock()
	defer mutex.Unlock()

	db, err := bolt.Open( DbPath, 0666, nil )
	if err != nil {
		return nil, err
	}
	defer db.Close()

	err = Init(db, dbBucketAggregator)
	if err != nil {
		return nil, err
	}

	aggregatedScans := make([]map[string]string, 0, scansPerTicket)
	aggregatedScans = append(aggregatedScans, currentScan)
	currentValue, err := dbSelect(db, dbBucketAggregator, plugin)
	if err != nil {
		return nil, err
	}

	if len(currentValue)>0 {
		var savedScans []map[string]string
		err = json.Unmarshal(currentValue, &savedScans)
		if err != nil {
			return nil, err
		}
		aggregatedScans = append(aggregatedScans, savedScans...)
	}

	if len(aggregatedScans) < scansPerTicket {
		saving, err := json.Marshal(aggregatedScans)
		if err != nil {
			return nil, err
		}

		err = dbInsert(db, dbBucketAggregator, []byte(plugin), saving)
		if err != nil {
			return nil, err
		}
		return nil, nil
	}
	dbInsert(db, dbBucketAggregator, []byte(plugin), nil)
	return aggregatedScans, nil
}
