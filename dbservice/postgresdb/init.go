package postgresdb

import (
	"github.com/jmoiron/sqlx"
)

var (
	tableSchemas = []string{
		"CREATE TABLE IF NOT EXISTS webhooktable (id varchar(32), date varchar(32), messagekey varchar(256),messagevalue text);",
		"CREATE TABLE IF NOT EXISTS webhookaggregator (id varchar(32), output varchar(32), saving text);",
		"CREATE TABLE IF NOT EXISTS webhookoutputstats (id varchar(32), outputname varchar(32), amount integer);",
		"CREATE TABLE IF NOT EXISTS webhooksharedconfig (id varchar(32), apikeyname varchar(14),value varchar(64));",
	}
)

var initAllTables = func(db *sqlx.DB) error {
	for _, schema := range tableSchemas {
		_, err := db.Exec(schema)
		if err != nil {
			return err
		}
	}
	return nil
}

var InitPostgresDb = func(connectUrl string) error {
	db, err := testConnect(connectUrl)
	if err != nil {
		return err
	}
	defer db.Close()

	err = initAllTables(db)
	if err != nil {
		return err
	}
	return nil
}
