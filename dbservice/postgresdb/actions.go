package postgresdb

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/aquasecurity/postee/dbservice/dbparam"
)

func (postgresDb *PostgresDb) MayBeStoreMessage(message []byte, messageKey string, expired *time.Time) (wasStored bool, err error) {
	db, err := psqlConnect(postgresDb.ConnectUrl)
	if err != nil {
		return false, err
	}
	defer db.Close()

	currentValue := ""
	sqlQuery := fmt.Sprintf("SELECT messageValue FROM %s WHERE (id=$1 AND messageKey=$2)", dbparam.DbBucketName)
	if err = db.Get(&currentValue, sqlQuery, postgresDb.Id, messageKey); err != nil {
		if err != sql.ErrNoRows {
			return false, err
		}
	}

	if currentValue != "" {
		return false, nil
	} else {
		if expired != nil {
			if err = insertInTableName(db, postgresDb.Id, messageKey, message, expired); err != nil {
				return false, err
			}
		} else {
			if err = insertInTableName(db, postgresDb.Id, messageKey, message, nil); err != nil {
				return false, err
			}
		}
		return true, nil
	}

}
