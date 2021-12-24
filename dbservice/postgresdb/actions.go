package postgresdb

import (
	"database/sql"
	"errors"
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
	sqlQuery := fmt.Sprintf("SELECT messageValue FROM %s WHERE (tenantName=$1 AND messageKey=$2)", dbparam.DbBucketName)
	if err = db.Get(&currentValue, sqlQuery, postgresDb.TenantName, messageKey); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return false, err
		}
	}

	if currentValue != "" {
		return false, nil
	} else {
		if err = insertInTableName(db, postgresDb.TenantName, messageKey, message, expired); err != nil {
			return false, err
		}
		return true, nil
	}
}
