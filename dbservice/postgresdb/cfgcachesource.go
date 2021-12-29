package postgresdb

import (
	"database/sql"
	"errors"
	"fmt"
	"log"

	"github.com/aquasecurity/postee/dbservice/dbparam"
)

const emptyCfg = `{"outputs":[],"routes":[],"templates":[]}`

var UpdateCfgCacheSource = func(postgresDb *PostgresDb, cfgfile string) error {
	connectUrl := postgresDb.ConnectUrl
	db, err := psqlConnect(connectUrl)
	if err != nil {
		return err
	}
	defer db.Close()
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
	defer db.Close()
	cfgFile := ""
	sqlQuery := fmt.Sprintf("SELECT configfile FROM %s WHERE tenantName=$1", dbparam.DbTableCfgCacheSource)
	if err = db.Get(&cfgFile, sqlQuery, postgresDb.TenantName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Printf("WARNING: %s doesn't include tenantName: %s, empty cfg is used", dbparam.DbTableCfgCacheSource, postgresDb.TenantName)
			return emptyCfg, nil
		}
		return "", fmt.Errorf("error getting cfg cache source: %v", err)
	}
	return cfgFile, nil
}
