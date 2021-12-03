package postgresdb

import (
	"fmt"
	"log"
	"time"
)

func (postgresDb *PostgresDb) CheckSizeLimit() {
	if DbSizeLimit == 0 {
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
	if err = db.Get(&size, fmt.Sprintf("SELECT pg_total_relation_size('%s');", dbTableName)); err != nil {
		log.Printf("CheckSizeLimit: Can't get db size")
		return
	}
	if size > DbSizeLimit {
		if err = deleteRowsById(db, dbTableName, postgresDb.Id); err != nil {
			log.Printf("CheckSizeLimit: Can't delete id's: %s from table: %s", postgresDb.Id, dbTableName)
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

	dates := []string{}
	if err := db.Select(&dates, fmt.Sprintf("SELECT %s FROM %s WHERE (%s=$1 and %s != '')", "date", dbTableName, "id", "date"), postgresDb.Id); err != nil {
		log.Printf("CheckExpiredData: Can't get dates from table: %s, err: %v", dbTableName, err)
		return
	}

	max := time.Now().UTC().Format(DateFmt) //remove expired records
	for _, date := range dates {
		if date <= max {
			if err = deleteRow(db, dbTableName, postgresDb.Id, "date", date); err != nil {
				log.Printf("CheckExpiredData: Can't delete %s from table:%s", date, dbTableName)
				return
			}
		}
	}
}
