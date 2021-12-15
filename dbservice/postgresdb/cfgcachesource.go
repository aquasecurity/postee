package postgresdb

import (
	"fmt"

	"github.com/aquasecurity/postee/dbservice/dbparam"
)

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
		return "", err
	}
	return cfgFile, nil
}
