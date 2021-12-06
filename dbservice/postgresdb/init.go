package postgresdb

import (
	"fmt"

	"github.com/aquasecurity/postee/dbservice/dbparam"
	"github.com/jmoiron/sqlx"
)

var (
	tableSchemas = []string{
		fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (id varchar(32), date timestamp, messagekey varchar(256), messagevalue bytea);", dbparam.DbBucketName),
		fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (id varchar(32), output varchar(32), saving bytea);", dbparam.DbBucketAggregator),
		fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (id varchar(32), outputname varchar(32), amount integer);", dbparam.DbBucketOutputStats),
		fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (id varchar(32), apikeyname varchar(14),value varchar(64));", dbparam.DbBucketSharedConfig),
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
