package postgresdb

import (
	"fmt"

	"github.com/jmoiron/sqlx"
)

var (
	tableSchemas = map[string]string{
		dbTableName:         "CREATE TABLE IF NOT EXISTS %s (id text, messagekey text,messagevalue text);",
		dbTableAggregator:   "CREATE TABLE IF NOT EXISTS %s (id text, output text,saving text);",
		dbTableExpiryDates:  "CREATE TABLE IF NOT EXISTS %s (id text, date text,messageKey text);",
		dbTableOutputStats:  "CREATE TABLE IF NOT EXISTS %s (id text, outputname text,amount integer);",
		dbTableSharedConfig: "CREATE TABLE IF NOT EXISTS %s (id text, apikeyname text,value text);",
	}
)

var initTable = func(db *sqlx.DB, tableName string) error {
	_, err := db.Exec(fmt.Sprintf(tableSchemas[tableName], tableName))
	if err != nil {
		return err
	}
	return nil
}
