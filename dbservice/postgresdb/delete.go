package postgresdb

import (
	"fmt"

	"github.com/jmoiron/sqlx"
)

var deleteRow = func(db *sqlx.DB, table, id, columnName, value string) error {
	if _, err := db.Exec(fmt.Sprintf("DELETE FROM %s WHERE (%s=$1 AND %s=$2);", table, "id", columnName), id, value); err != nil {
		return err
	}
	return nil
}

var deleteRowsById = func(db *sqlx.DB, table, id string) error {
	if _, err := db.Exec(fmt.Sprintf("DELETE FROM %s WHERE %s=$1", table, "id"), id); err != nil {
		return err
	}
	return nil
}
