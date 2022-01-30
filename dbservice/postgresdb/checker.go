package postgresdb

import (
	"fmt"
	"time"

	"github.com/aquasecurity/postee/dbservice/dbparam"
	"github.com/aquasecurity/postee/log"
)

func (postgresDb *PostgresDb) CheckSizeLimit() {
	if dbparam.DbSizeLimit == 0 {
		return
	}

	connectUrl := postgresDb.ConnectUrl
	db, err := psqlConnect(connectUrl)
	if err != nil {
		log.Logger.Errorf("CheckSizeLimit: Can't open db, connectUrl: %s", connectUrl)
		return
	}

	size := 0
	if err = db.Get(&size, fmt.Sprintf("SELECT pg_total_relation_size('%s');", dbparam.DbBucketName)); err != nil {
		log.Logger.Error("CheckSizeLimit: Can't get db size")
		return
	}
	if size > dbparam.DbSizeLimit {
		if err = deleteRowsByTenantName(db, dbparam.DbBucketName, postgresDb.TenantName); err != nil {
			log.Logger.Errorf("CheckSizeLimit: Can't delete tenantName's: %s from table: %s", postgresDb.TenantName, dbparam.DbBucketName)
			return
		}
	}
}

func (postgresDb *PostgresDb) CheckExpiredData() {
	connectUrl := postgresDb.ConnectUrl
	db, err := psqlConnect(connectUrl)
	if err != nil {
		log.Logger.Errorf("CheckExpiredData: Can't open postgresDb: %v", err)
		return
	}

	max := time.Now().UTC() //remove expired records
	if err = deleteRowsByTenantNameAndTime(db, postgresDb.TenantName, max); err != nil {
		log.Logger.Errorf("CheckExpiredData: Can't delete dates from table:%s, err: %v", dbparam.DbBucketName, err)
	}
}
