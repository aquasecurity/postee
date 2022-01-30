package postgresdb

import (
	"errors"
	"sync"
	"time"

	"github.com/aquasecurity/postee/log"
	"github.com/jmoiron/sqlx"
)

const (
	CONN_RETRIES = 10
)

var (
	once   sync.Once
	dbConn *sqlx.DB
)

var psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
	once.Do(func() {
		retries := CONN_RETRIES
		db, err := sqlx.Connect("postgres", connectUrl)
		for err != nil {
			log.Logger.Errorf("failed to connect to postgres db (%d): %s", retries, err.Error())

			if retries > 1 {
				retries--
				time.Sleep(5 * time.Second)
				db, err = sqlx.Connect("postgres", connectUrl)
				continue
			}
			log.Logger.Fatal(err)
		}
		dbConn = db
	})

	return dbConn, nil
}

var testConnect = func(connectUrl string) (*sqlx.DB, error) {
	db, err := psqlConnect(connectUrl)
	if err != nil {
		return nil, errors.New("Error postgresDb test connect: " + err.Error())
	}
	return db, nil
}
