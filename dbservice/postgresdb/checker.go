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

	psqlInfo := postgresDb.psqlInfo
	db, err := psqlConnect(psqlInfo)
	if err != nil {
		log.Println("CheckSizeLimit: Can't open db, psqlInfo: ", psqlInfo)
		return
	}
	defer db.Close()

	size := 0
	if err = db.Get(&size, fmt.Sprintf("SELECT pg_total_relation_size('%s');", dbTableName)); err != nil {
		log.Printf("CheckSizeLimit: Can't get db size")
		return
	}
	if size > DbSizeLimit {
		if err = deleteRowsById(db, dbTableName, postgresDb.id); err != nil {
			log.Printf("CheckSizeLimit: Can't delete id's: %s from table: %s", postgresDb.id, dbTableName)
			return
		}
	}
}

func (postgresDb *PostgresDb) CheckExpiredData() {
	psqlInfo := postgresDb.psqlInfo
	db, err := psqlConnect(psqlInfo)
	if err != nil {
		log.Println("CheckExpiredData: Can't open db, psqlInfo: ", psqlInfo)
		return
	}
	defer db.Close()

	var scanStructs []struct {
		Date   string `db:"date"`
		TtlKey string `db:"messagekey"`
	}
	if err := db.Select(&scanStructs, fmt.Sprintf("SELECT (key AND ttlkey) FROM %s WHERE %s=$1", dbTableExpiryDates, "id"), postgresDb.id); err != nil {
		log.Printf("CheckExpiredData: Can't get %s table: %s", dbTableExpiryDates, err)
		return
	}

	max := time.Now().UTC().Format(DateFmt) //remove expired records
	for _, scanStruct := range scanStructs {
		if scanStruct.Date <= max {

			if err = deleteRow(db, dbTableExpiryDates, postgresDb.id, "messagekey", scanStruct.TtlKey); err != nil {
				log.Printf("CheckExpiredData: Can't delete %s from table:%s", scanStruct.TtlKey, dbTableExpiryDates)
				return
			}

			if err = deleteRow(db, dbTableName, postgresDb.id, "messagekey", scanStruct.TtlKey); err != nil {
				log.Printf("CheckExpiredData: Can't delete %s from table:%s", scanStruct.TtlKey, dbTableName)
				return
			}
		}
	}
}
