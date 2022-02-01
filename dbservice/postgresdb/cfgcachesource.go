package postgresdb

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/aquasecurity/postee/v2/dbservice/dbparam"
)

const emptyCfg = `{}`

var UpdateCfgCacheSource = func(postgresDb *PostgresDb, cfgfile string) error {
	connectUrl := postgresDb.ConnectUrl
	db, err := psqlConnect(connectUrl)
	if err != nil {
		return err
	}

	if err := insertCfgCacheSource(db, postgresDb.TenantName, cfgfile); err != nil {
		return err
	}
	return nil
}

var GetCfgCacheSource = func(postgresDb *PostgresDb) (string, error) {
	connectUrl := postgresDb.ConnectUrl
	db, err := psqlConnect(connectUrl)
	if err != nil {
		return "", err
	}

	cfgFile := ""
	sqlQuery := fmt.Sprintf("SELECT configfile FROM %s WHERE tenantName=$1", dbparam.DbTableCfgCacheSource)
	if err = db.Get(&cfgFile, sqlQuery, postgresDb.TenantName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return emptyCfg, nil
		}
		return "", fmt.Errorf("error getting cfg cache source: %w", err)
	}
	return cfgFile, nil
}
