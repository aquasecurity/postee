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
	} else if i == 1 {
		if _, err := db.Exec(fmt.Sprintf("UPDATE %s SET %s=$1 WHERE (%s=$2 AND %s=$3);", table, columnName3, "id", columnName2), value3, id, value2); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("error insert in postgresDb. Table:%s where id=%s, %s=%s, have %d rows", table, id, columnName2, value2, i)
	}
	return nil
}

var insertInTableName = func(db *sqlx.DB, id, date, messageKey, messageValue string) error {
	var i int
	if err := db.Get(&i, fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE (%s=$1 AND %s=$2)", dbTableName, "id", "messageKey"), id, messageKey); err != nil {
		return err
	}
	if i == 0 {
		if _, err := db.Exec(fmt.Sprintf("INSERT INTO %s (%s, %s, %s, %s) VALUES ($1, $2, $3, $4)", dbTableName, "id", "date", "messagekey", "messagevalue"),
			id, date, messageKey, messageValue); err != nil {
			return err
		}
	} else if i == 1 {
		if _, err := db.Exec(fmt.Sprintf("UPDATE %s SET %s=$1, %s=$2 WHERE (%s=$3 AND %s=$4);", dbTableName, "date", "messagevalue", "id", "messagekey"),
			date, messageValue, id, messageKey); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("error insert in postgresDb. Table:%s where id=%s, messageKey=%s, have %d rows", dbTableName, id, messageKey, i)
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
	} else if i == 1 {
		_, err = db.Exec(fmt.Sprintf("UPDATE %s SET %s=$1 WHERE (%s=$2 AND %s=$3);", dbTableOutputStats, "amount", "id", "outputName"), amount, id, outputName)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("error insert in postgresDb. Table:%s where id=%s, outputName=%s, have %d rows", dbTableOutputStats, id, outputName, i)
	}

	return nil
}
