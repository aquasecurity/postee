package postgresdb

import (
	"errors"

	"github.com/jmoiron/sqlx"
)

var psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
	db, err := sqlx.Connect("postgres", connectUrl)
	if err != nil {
		return nil, err
	}
	return db, nil
}

var testConnect = func(connectUrl string) (*sqlx.DB, error) {
	db, err := psqlConnect(connectUrl)
	if err != nil {
		return nil, errors.New("Error postgresDb test connect: " + err.Error())
	}
	return db, nil
}
