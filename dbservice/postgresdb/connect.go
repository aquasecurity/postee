package postgresdb

import (
	"errors"
	"time"

	"github.com/aquasecurity/postee/log"
	"github.com/jmoiron/sqlx"
)

const (
	CONN_RETRIES = 10
)

var dbConn *sqlx.DB

var psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
	if dbConn == nil {
		retries := CONN_RETRIES
		db, err := sqlx.Connect("postgres", connectUrl)
		for err != nil {
			if log.Logger != nil {
				log.Logger.Errorf("failed to connect to postgres db (%d): %s", retries, err.Error())
			}

			if retries > 1 {
				retries--
				time.Sleep(5 * time.Second)
				db, err = sqlx.Connect("postgres", connectUrl)
				continue
			}
			return nil, err
		}
		dbConn = db
	}

	return dbConn, nil
}

var testConnect = func(connectUrl string) (*sqlx.DB, error) {
	db, err := psqlConnect(connectUrl)
	if err != nil {
		return nil, errors.New("Error postgresDb test connect: " + err.Error())
	}
	return db, nil
}
