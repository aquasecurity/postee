package postgresdb

import (
	"fmt"
	"log"
	"time"

	"github.com/aquasecurity/postee/dbservice/dbparam"
)

func (postgresDb *PostgresDb) CheckSizeLimit() {
	if dbparam.DbSizeLimit == 0 {
		return
	}

	connectUrl := postgresDb.ConnectUrl
	db, err := psqlConnect(connectUrl)
	if err != nil {
		log.Println("CheckSizeLimit: Can't open db, connectUrl: ", connectUrl)
		return
	}
	defer db.Close()

	size := 0
	if err = db.Get(&size, fmt.Sprintf("SELECT pg_total_relation_size('%s');", dbparam.DbBucketName)); err != nil {
		log.Printf("CheckSizeLimit: Can't get db size")
		return
	}
	if size > dbparam.DbSizeLimit {
		if err = deleteRowsById(db, dbparam.DbBucketName, postgresDb.Id); err != nil {
			log.Printf("CheckSizeLimit: Can't delete id's: %s from table: %s", postgresDb.Id, dbparam.DbBucketName)
			return
		}
	}
}

func (postgresDb *PostgresDb) CheckExpiredData() {
	connectUrl := postgresDb.ConnectUrl
	db, err := psqlConnect(connectUrl)
	if err != nil {
		log.Printf("CheckExpiredData: Can't open postgresDb: %v", err)
		return
	}
	defer db.Close()

	max := time.Now().UTC() //remove expired records
	if err = deleteRowsByIdAndTime(db, dbparam.DbBucketName, postgresDb.Id, max); err != nil {
		log.Printf("CheckExpiredData: Can't delete dates from table:%s, err: %v", dbparam.DbBucketName, err)
	}
}
