package postgresdb

import (
	"fmt"

	"github.com/jmoiron/sqlx"
)

var insert = func(db *sqlx.DB, table, id, columnName2, value2, columnName3, value3 string) error {
	var i int
	if err := db.Get(&i, fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE (%s=$1 AND %s=$2)", table, "id", columnName2), id, value2); err != nil {
		return err
	}
	if i == 0 {
		if _, err := db.Exec(fmt.Sprintf("INSERT INTO %s (%s, %s, %s) VALUES ($1, $2, $3)", table, "id", columnName2, columnName3), id, value2, value3); err != nil {
			return err
		}
	} else {
		if _, err := db.Exec(fmt.Sprintf("UPDATE %s SET %s=$1 WHERE (%s=$2 AND %s=$3);", table, columnName3, "id", columnName2), value3, id, value2); err != nil {
			return err
		}
	}
	return nil
}

var insertOutputStats = func(db *sqlx.DB, id, outputName string, amount int) error {
	var i int
	err := db.Get(&i, fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE (%s=$1 AND %s=$2)", dbTableOutputStats, "id", "outputName"), id, outputName)
	if err != nil {
		return err
	}
	if i == 0 {
		_, err := db.Exec(fmt.Sprintf("INSERT INTO %s (%s, %s, %s) VALUES ($1, $2, $3);", dbTableOutputStats, "id", "outputName", "amount"), id, outputName, amount)
		if err != nil {
			return err
		}
	} else {
		_, err = db.Exec(fmt.Sprintf("UPDATE %s SET %s=$1 WHERE (%s=$2 AND %s=$3);", dbTableOutputStats, "amount", "id", "outputName"), amount, id, outputName)
		if err != nil {
			return err
		}
	}
	return nil
}
