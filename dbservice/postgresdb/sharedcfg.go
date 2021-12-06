package postgresdb

import (
	"fmt"

	"github.com/aquasecurity/postee/dbservice/dbparam"
	_ "github.com/lib/pq"
)

var apiKeyName = "POSTEE_API_KEY"

func (postgresDb *PostgresDb) EnsureApiKey() error {
	db, err := psqlConnect(postgresDb.ConnectUrl)
	if err != nil {
		return err
	}
	defer db.Close()

	apiKey, err := dbparam.GenerateApiKey(32)
	if err != nil {
		return err
	}

	if err = insertInTableSharedConfig(db, postgresDb.Id, apiKeyName, apiKey); err != nil {
		return err
	}

	return nil
}

func (postgresDb *PostgresDb) GetApiKey() (string, error) {
	db, err := psqlConnect(postgresDb.ConnectUrl)
	if err != nil {
		return "", err
	}
	defer db.Close()
	value := ""
	sqlQuery := fmt.Sprintf("SELECT %s FROM %s WHERE (id=$1 AND %s=$2)", "value", dbparam.DbBucketSharedConfig, "apikeyname")
	err = db.Get(&value, sqlQuery, postgresDb.Id, apiKeyName)
	if err != nil {
		return "", err
	}
	return value, nil

}
