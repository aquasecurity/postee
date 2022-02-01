package postgresdb

import (
	"fmt"
	"time"

	"github.com/aquasecurity/postee/v2/dbservice/dbparam"
	"github.com/jmoiron/sqlx"
)

var insertInTableSharedConfig = func(db *sqlx.DB, tenantName, apikeyname, value string) error {
	var i int
	sqlQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE (tenantName=$1 AND apikeyname=$2)", dbparam.DbBucketSharedConfig)
	if err := db.Get(&i, sqlQuery, tenantName, apikeyname); err != nil {
		return err
	}
	if i == 0 {
		sqlQuery = fmt.Sprintf("INSERT INTO %s (tenantName, apikeyname, value) VALUES ($1, $2, $3)", dbparam.DbBucketSharedConfig)
		if _, err := db.Exec(sqlQuery, tenantName, apikeyname, value); err != nil {
			return err
		}
	} else if i == 1 {
		sqlQuery = fmt.Sprintf("UPDATE %s SET value=$1 WHERE (tenantName=$2 AND apikeyname=$3);", dbparam.DbBucketSharedConfig)
		if _, err := db.Exec(sqlQuery, value, tenantName, apikeyname); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("error insert in postgresDb. Table:%s where tenantName=%s, apikeyname=%s, have %d rows", dbparam.DbBucketSharedConfig, tenantName, apikeyname, i)
	}
	return nil
}

var insertInTableAggregator = func(db *sqlx.DB, tenantName, output string, saving []byte) error {
	var i int
	sqlQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE (tenantName=$1 AND output=$2)", dbparam.DbBucketAggregator)
	if err := db.Get(&i, sqlQuery, tenantName, output); err != nil {
		return err
	}
	if i == 0 {
		sqlQuery = fmt.Sprintf("INSERT INTO %s (tenantName, output, saving) VALUES ($1, $2, $3)", dbparam.DbBucketAggregator)
		if _, err := db.Exec(sqlQuery, tenantName, output, saving); err != nil {
			return err
		}
	} else if i == 1 {
		sqlQuery = fmt.Sprintf("UPDATE %s SET saving=$1 WHERE (tenantName=$2 AND output=$3);", dbparam.DbBucketAggregator)
		if _, err := db.Exec(sqlQuery, saving, tenantName, output); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("error insert in postgresDb. Table:%s where tenantName=%s, output=%s, have %d rows", dbparam.DbBucketAggregator, tenantName, output, i)
	}
	return nil
}

var insertInTableName = func(db *sqlx.DB, tenantName, messageKey string, messageValue []byte, date *time.Time) error {
	var i int
	sqlQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE (tenantName=$1 AND %s=$2)", dbparam.DbBucketName, "messageKey")
	if err := db.Get(&i, sqlQuery, tenantName, messageKey); err != nil {
		return err
	}
	if i == 0 {
		sqlQuery = fmt.Sprintf("INSERT INTO %s (tenantName, %s, %s, %s) VALUES ($1, $2, $3, $4)", dbparam.DbBucketName, "date", "messagekey", "messagevalue")
		if _, err := db.Exec(sqlQuery, tenantName, date, messageKey, messageValue); err != nil {
			return err
		}
	} else if i == 1 {
		sqlQuery = fmt.Sprintf("UPDATE %s SET %s=$1, %s=$2 WHERE (tenantName=$3 AND %s=$4);", dbparam.DbBucketName, "date", "messagevalue", "messagekey")
		if _, err := db.Exec(sqlQuery, date, messageValue, tenantName, messageKey); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("error insert in postgresDb. Table:%s where tenantName=%s, messageKey=%s, have %d rows", dbparam.DbBucketName, tenantName, messageKey, i)
	}
	return nil
}

var insertOutputStats = func(db *sqlx.DB, tenantName, outputName string, amount int) error {
	var i int
	sqlQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE (tenantName=$1 AND %s=$2)", dbparam.DbBucketOutputStats, "outputName")
	err := db.Get(&i, sqlQuery, tenantName, outputName)
	if err != nil {
		return err
	}
	if i == 0 {
		sqlQuery = fmt.Sprintf("INSERT INTO %s (tenantName, %s, %s) VALUES ($1, $2, $3);", dbparam.DbBucketOutputStats, "outputName", "amount")
		_, err := db.Exec(sqlQuery, tenantName, outputName, amount)
		if err != nil {
			return err
		}
	} else if i == 1 {
		sqlQuery = fmt.Sprintf("UPDATE %s SET %s=$1 WHERE (tenantName=$2 AND %s=$3);", dbparam.DbBucketOutputStats, "amount", "outputName")
		_, err = db.Exec(sqlQuery, amount, tenantName, outputName)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("error insert in postgresDb. Table:%s where tenantName=%s, outputName=%s, have %d rows", dbparam.DbBucketOutputStats, tenantName, outputName, i)
	}
	return nil
}

var insertCfgCacheSource = func(db *sqlx.DB, tenantName, cfgFile string) error {
	var i int
	sqlQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE tenantName=$1", dbparam.DbTableCfgCacheSource)
	err := db.Get(&i, sqlQuery, tenantName)
	if err != nil {
		return err
	}
	if i == 0 {
		sqlQuery = fmt.Sprintf("INSERT INTO %s (tenantName, configfile) VALUES ($1, $2);", dbparam.DbTableCfgCacheSource)
		_, err := db.Exec(sqlQuery, tenantName, cfgFile)
		if err != nil {
			return err
		}
	} else if i == 1 {
		sqlQuery = fmt.Sprintf("UPDATE %s SET configfile=$1 WHERE tenantName=$2;", dbparam.DbTableCfgCacheSource)
		_, err = db.Exec(sqlQuery, cfgFile, tenantName)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("error insert in postgresDb. Table:%s where tenantName=%s, have %d rows", dbparam.DbTableCfgCacheSource, tenantName, i)
	}
	return nil
}
