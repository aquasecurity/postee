package postgresdb

import (
	"database/sql"
	"fmt"
	"time"
)

func (postgresDb *PostgresDb) MayBeStoreMessage(message []byte, messageKey string, expired *time.Time) (wasStored bool, err error) {
	db, err := psqlConnect(postgresDb.ConnectUrl)
	if err != nil {
		return false, err
	}
	defer db.Close()

	currentValue := ""
	sqlQuery := fmt.Sprintf("SELECT %s FROM %s WHERE (%s=$1 AND %s=$2)", "messageValue", dbTableName, "id", "messageKey")
	if err = db.Get(&currentValue, sqlQuery, postgresDb.Id, messageKey); err != nil {
		if err != sql.ErrNoRows {
			return false, err
		}
	}

	if currentValue != "" {
		return false, nil
	} else {
		if expired != nil {
			if err = insertInTableName(db, postgresDb.Id, expired.Format(DateFmt), messageKey, string(message)); err != nil {
				return false, err
			}
		} else {
			if err = insertInTableName(db, postgresDb.Id, "", messageKey, string(message)); err != nil {
				return false, err
			}
		}
		return true, nil
	}

}
