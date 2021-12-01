package postgresdb

import (
	"database/sql"
	"encoding/json"
	"fmt"
)

func (postgresDb *PostgresDb) AggregateScans(output string,
	currentScan map[string]string,
	scansPerTicket int,
	ignoreTheQuantity bool) ([]map[string]string, error) {

	db, err := psqlConnect(postgresDb.ConnectUrl)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	if err = initTable(db, dbTableAggregator); err != nil {
		return nil, err
	}

	aggregatedScans := make([]map[string]string, 0, scansPerTicket)
	if len(currentScan) > 0 {
		aggregatedScans = append(aggregatedScans, currentScan)
	}
	currentValue := ""
	if err = db.Get(&currentValue, fmt.Sprintf("SELECT %s FROM %s WHERE (%s=$1 AND %s=$2)", "saving", dbTableAggregator, "id", "output"), postgresDb.Id, output); err != nil {
		if err != sql.ErrNoRows {
			return nil, err
		}
	}

	if currentValue != "" {
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
		if err = insert(db, dbTableAggregator, postgresDb.Id, "output", output, "saving", string(saving)); err != nil {

			return nil, err
		}
		return nil, nil
	}
	if err = insert(db, dbTableAggregator, postgresDb.Id, "output", output, "saving", ""); err != nil {
		return nil, err
	}
	return aggregatedScans, nil
}
