package postgresdb

import (
	"errors"
	"time"

	"github.com/jmoiron/sqlx"
)

var (
	dbTableName         = "WebhookTable"
	dbTableAggregator   = "WebhookAggregator"
	dbTableExpiryDates  = "WebhookExpiryDates"
	dbTableOutputStats  = "WebhookOutputStats"
	dbTableSharedConfig = "WebhookSharedConfig"

	DbSizeLimit = 0
	DateFmt     = time.RFC3339Nano
	dueTimeBase = time.Hour * time.Duration(24)
)

type PostgresDb struct {
	ConnectUrl string
	Id         string
}

func NewPostgresDb(id, connectUrl string) *PostgresDb {
	return &PostgresDb{
		ConnectUrl: connectUrl,
		Id:         id,
	}
}

func (postgresDb *PostgresDb) SetDbSizeLimit(limit int) {
	DbSizeLimit = limit
}

var TestConnect = func(connectUrl string) error {
	db, err := psqlConnect(connectUrl)
	if err != nil {
		return errors.New("Error postgresDb test connect: " + err.Error())
	}
	defer db.Close()
	return nil
}

var psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
	db, err := sqlx.Connect("postgres", connectUrl)
	if err != nil {
		return nil, err
	}
	return db, nil
}
