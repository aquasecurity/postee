package postgresdb

import (
	"database/sql"
	"fmt"
	"time"
)

func (postgresDb *PostgresDb) MayBeStoreMessage(message []byte, messageKey string, expired *time.Time) (wasStored bool, err error) {
	db, err := psqlConnect(postgresDb.psqlInfo)
	if err != nil {
		return false, err
	}
	defer db.Close()

	if err = initTable(db, dbTableName); err != nil {
		return false, err
	}

	if err = initTable(db, dbTableExpiryDates); err != nil {
		return false, err
	}

	currentValue := ""
	if err = db.Get(&currentValue, fmt.Sprintf("SELECT %s FROM %s WHERE (%s=$1 AND %s=$2)", "messageValue", dbTableName, "id", "messageKey"), postgresDb.id, messageKey); err != nil {
		if err != sql.ErrNoRows {
			return false, err
		}
	}

	if currentValue != "" {
		return false, nil
	} else {

		if err = insert(db, dbTableName, postgresDb.id, "messagekey", messageKey, "messagevalue", string(message)); err != nil {
			return false, err
		}
		if expired != nil {

			if err = insert(db, dbTableExpiryDates, postgresDb.id, "date", expired.Format(DateFmt), "messagekey", messageKey); err != nil {
				return false, err
			}
		}
		return true, nil
	}

}
