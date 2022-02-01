package postgresdb

import (
	"fmt"

	"github.com/aquasecurity/postee/v2/dbservice/dbparam"
	_ "github.com/lib/pq"
)

var apiKeyName = "POSTEE_API_KEY"

func (postgresDb *PostgresDb) EnsureApiKey() error {
	db, err := psqlConnect(postgresDb.ConnectUrl)
	if err != nil {
		return err
	}

	apiKey, err := dbparam.GenerateApiKey(32)
	if err != nil {
		return err
	}

	if err = insertInTableSharedConfig(db, postgresDb.TenantName, apiKeyName, apiKey); err != nil {
		return err
	}
	return nil
}

func (postgresDb *PostgresDb) GetApiKey() (string, error) {
	db, err := psqlConnect(postgresDb.ConnectUrl)
	if err != nil {
		return "", err
	}

	value := ""
	sqlQuery := fmt.Sprintf("SELECT %s FROM %s WHERE (tenantName=$1 AND %s=$2)", "value", dbparam.DbBucketSharedConfig, "apikeyname")
	err = db.Get(&value, sqlQuery, postgresDb.TenantName, apiKeyName)
	if err != nil {
		return "", err
	}
	return value, nil
}
