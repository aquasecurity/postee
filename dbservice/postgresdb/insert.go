package postgresdb

import (
	"fmt"
	"time"

	"github.com/aquasecurity/postee/dbservice/dbparam"
	"github.com/jmoiron/sqlx"
)

var insertInTableSharedConfig = func(db *sqlx.DB, id, apikeyname, value string) error {
	var i int
	sqlQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE (id=$1 AND apikeyname=$2)", dbparam.DbBucketSharedConfig)
	if err := db.Get(&i, sqlQuery, id, apikeyname); err != nil {
		return err
	}
	if i == 0 {
		sqlQuery = fmt.Sprintf("INSERT INTO %s (id, apikeyname, value) VALUES ($1, $2, $3)", dbparam.DbBucketSharedConfig)
		if _, err := db.Exec(sqlQuery, id, apikeyname, value); err != nil {
			return err
		}
	} else if i == 1 {
		sqlQuery = fmt.Sprintf("UPDATE %s SET value=$1 WHERE (id=$2 AND apikeyname=$3);", dbparam.DbBucketSharedConfig)
		if _, err := db.Exec(sqlQuery, value, id, apikeyname); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("error insert in postgresDb. Table:%s where id=%s, apikeyname=%s, have %d rows", dbparam.DbBucketSharedConfig, id, apikeyname, i)
	}
	return nil
}

var insertInTableAggregator = func(db *sqlx.DB, id, output string, saving []byte) error {
	var i int
	sqlQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE (id=$1 AND output=$2)", dbparam.DbBucketAggregator)
	if err := db.Get(&i, sqlQuery, id, output); err != nil {
		return err
	}
	if i == 0 {
		sqlQuery = fmt.Sprintf("INSERT INTO %s (id, output, saving) VALUES ($1, $2, $3)", dbparam.DbBucketAggregator)
		if _, err := db.Exec(sqlQuery, id, output, saving); err != nil {
			return err
		}
	} else if i == 1 {
		sqlQuery = fmt.Sprintf("UPDATE %s SET saving=$1 WHERE (id=$2 AND output=$3);", dbparam.DbBucketAggregator)
		if _, err := db.Exec(sqlQuery, saving, id, output); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("error insert in postgresDb. Table:%s where id=%s, output=%s, have %d rows", dbparam.DbBucketAggregator, id, output, i)
	}
	return nil
}

var insertInTableName = func(db *sqlx.DB, id, messageKey string, messageValue []byte, date *time.Time) error {
	var i int
	sqlQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE (id=$1 AND %s=$2)", dbparam.DbBucketName, "messageKey")
	if err := db.Get(&i, sqlQuery, id, messageKey); err != nil {
		return err
	}
	if i == 0 {
		sqlQuery = fmt.Sprintf("INSERT INTO %s (id, %s, %s, %s) VALUES ($1, $2, $3, $4)", dbparam.DbBucketName, "date", "messagekey", "messagevalue")
		if _, err := db.Exec(sqlQuery, id, date, messageKey, messageValue); err != nil {
			return err
		}
	} else if i == 1 {
		sqlQuery = fmt.Sprintf("UPDATE %s SET %s=$1, %s=$2 WHERE (id=$3 AND %s=$4);", dbparam.DbBucketName, "date", "messagevalue", "messagekey")
		if _, err := db.Exec(sqlQuery, date, messageValue, id, messageKey); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("error insert in postgresDb. Table:%s where id=%s, messageKey=%s, have %d rows", dbparam.DbBucketName, id, messageKey, i)
	}
	return nil
}

var insertOutputStats = func(db *sqlx.DB, id, outputName string, amount int) error {
	var i int
	sqlQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE (id=$1 AND %s=$2)", dbparam.DbBucketOutputStats, "outputName")
	err := db.Get(&i, sqlQuery, id, outputName)
	if err != nil {
		return err
	}
	if i == 0 {
		sqlQuery = fmt.Sprintf("INSERT INTO %s (id, %s, %s) VALUES ($1, $2, $3);", dbparam.DbBucketOutputStats, "outputName", "amount")
		_, err := db.Exec(sqlQuery, id, outputName, amount)
		if err != nil {
			return err
		}
	} else if i == 1 {
		sqlQuery = fmt.Sprintf("UPDATE %s SET %s=$1 WHERE (id=$2 AND %s=$3);", dbparam.DbBucketOutputStats, "amount", "outputName")
		_, err = db.Exec(sqlQuery, amount, id, outputName)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("error insert in postgresDb. Table:%s where id=%s, outputName=%s, have %d rows", dbparam.DbBucketOutputStats, id, outputName, i)
	}

	return nil
}
