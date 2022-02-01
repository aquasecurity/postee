package postgresdb

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aquasecurity/postee/v2/dbservice/dbparam"
)

func (postgresDb *PostgresDb) AggregateScans(output string,
	currentScan map[string]string,
	scansPerTicket int,
	ignoreTheQuantity bool) ([]map[string]string, error) {

	db, err := psqlConnect(postgresDb.ConnectUrl)
	if err != nil {
		return nil, err
	}

	aggregatedScans := make([]map[string]string, 0, scansPerTicket)
	if len(currentScan) > 0 {
		aggregatedScans = append(aggregatedScans, currentScan)
	}
	currentValue := []byte{}
	sqlQuery := fmt.Sprintf("SELECT %s FROM %s WHERE (tenantName=$1 AND %s=$2)", "saving", dbparam.DbBucketAggregator, "output")
	if err = db.Get(&currentValue, sqlQuery, postgresDb.TenantName, output); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	}

	if len(currentValue) > 0 {
		var savedScans []map[string]string
		err = json.Unmarshal([]byte(currentValue), &savedScans)
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
		if err = insertInTableAggregator(db, postgresDb.TenantName, output, saving); err != nil {

			return nil, err
		}
		return nil, nil
	}
	if err = insertInTableAggregator(db, postgresDb.TenantName, output, nil); err != nil {
		return nil, err
	}
	return aggregatedScans, nil
}
