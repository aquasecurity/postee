package postgresdb

import (
	"fmt"
	"time"

	"github.com/aquasecurity/postee/dbservice/dbparam"
	"github.com/jmoiron/sqlx"
)

var deleteRowsByTenantNameAndTime = func(db *sqlx.DB, tenantName string, t time.Time) error {
	sqlQuery := fmt.Sprintf("DELETE FROM %s WHERE (tenantName=$1 AND date < $2)", dbparam.DbBucketName)
	if _, err := db.Exec(sqlQuery, tenantName, t); err != nil {
		return err
	}
	return nil
}

var deleteRowsByTenantName = func(db *sqlx.DB, table, tenantName string) error {
	sqlQuery := fmt.Sprintf("DELETE FROM %s WHERE tenantName=$1", table)
	if _, err := db.Exec(sqlQuery, tenantName); err != nil {
		return err
	}
	return nil
}
