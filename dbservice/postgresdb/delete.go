package postgresdb

import (
	"fmt"
	"time"

	"github.com/aquasecurity/postee/dbservice/dbparam"
	"github.com/jmoiron/sqlx"
)

var deleteRowsByIdAndTime = func(db *sqlx.DB, id string, t time.Time) error {
	sqlQuery := fmt.Sprintf("DELETE FROM %s WHERE (id=$1 AND date < $2)", dbparam.DbBucketName)
	if _, err := db.Exec(sqlQuery, id, t); err != nil {
		return err
	}
	return nil
}

var deleteRowsById = func(db *sqlx.DB, table, id string) error {
	sqlQuery := fmt.Sprintf("DELETE FROM %s WHERE id=$1", table)
	if _, err := db.Exec(sqlQuery, id); err != nil {
		return err
	}
	return nil
}

// var deleteRowsByIdAndOutput = func(db *sqlx.DB, id, output string) error {
// 	sqlQuery := fmt.Sprintf("DELETE FROM %s WHERE (id=$1 AND output=$2)", dbparam.DbBucketAggregator)
// 	if _, err := db.Exec(sqlQuery, id, output); err != nil {
// 		return err
// 	}
// 	return nil
// }
