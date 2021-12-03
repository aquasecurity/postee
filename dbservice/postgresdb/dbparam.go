package postgresdb

import (
	"time"
)

var (
	dbTableName         = "WebhookTable"
	dbTableAggregator   = "WebhookAggregator"
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
