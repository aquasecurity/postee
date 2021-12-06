package postgresdb

import (
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
)

var deleteRowsByIdAndTime = func(db *sqlx.DB, table, id string, t time.Time) error {
	sqlQuery := fmt.Sprintf("DELETE FROM %s WHERE (id=$1 and date < $2)", table)
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
