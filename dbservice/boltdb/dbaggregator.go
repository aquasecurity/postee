package boltdb

import (
	"encoding/json"

	"github.com/aquasecurity/postee/dbservice/dbparam"
)

func (boltDb *BoltDb) AggregateScans(output string,
	currentScan map[string]string,
	scansPerTicket int,
	ignoreTheQuantity bool) ([]map[string]string, error) {
	boltDb.mu.Lock()
	defer boltDb.mu.Unlock()

	db := boltDb.db

	err := Init(db, dbparam.DbBucketAggregator)
	if err != nil {
		return nil, err
	}

	aggregatedScans := make([]map[string]string, 0, scansPerTicket)
	if len(currentScan) > 0 {
		aggregatedScans = append(aggregatedScans, currentScan)
	}
	currentValue, err := dbSelect(db, dbparam.DbBucketAggregator, output)
	if err != nil {
		return nil, err
	}

	if len(currentValue) > 0 {
		var savedScans []map[string]string
		err = json.Unmarshal(currentValue, &savedScans)
		if err != nil {
			return nil, err
		}
		aggregatedScans = append(aggregatedScans, savedScans...)
	}

	if ignoreTheQuantity || len(aggregatedScans) < scansPerTicket {
		saving, err := json.Marshal(aggregatedScans)
		if err != nil {
			return nil, err
		}

		err = dbInsert(db, dbparam.DbBucketAggregator, []byte(output), saving)
		if err != nil {
			return nil, err
		}
		return nil, nil
	}
	err = dbInsert(db, dbparam.DbBucketAggregator, []byte(output), nil)
	if err != nil {
		return nil, err
	}
	return aggregatedScans, nil
}
