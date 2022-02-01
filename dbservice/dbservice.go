package dbservice

import (
	"fmt"
	"time"

	"github.com/aquasecurity/postee/v2/dbservice/boltdb"
	"github.com/aquasecurity/postee/v2/dbservice/postgresdb"
)

var (
	Db DbProvider

	errConfigPsqlEmptyTenantName = fmt.Errorf("error configuring postgres: 'tenantName' is empty")
)

type DbProvider interface {
	MayBeStoreMessage(message []byte, messageKey string, expired *time.Time) (wasStored bool, err error)
	CheckSizeLimit()
	CheckExpiredData()
	AggregateScans(output string, currentScan map[string]string, scansPerTicket int, ignoreTheQuantity bool) ([]map[string]string, error)
	RegisterPlgnInvctn(name string) error
	EnsureApiKey() error
	GetApiKey() (string, error)
	Close() error
}

func ConfigureDb(pathToDb, postgresUrl, tenantName string) (DbProvider, error) {
	if postgresUrl != "" {
		if tenantName == "" {
			return nil, errConfigPsqlEmptyTenantName
		}
		postgresDb := postgresdb.NewPostgresDb(tenantName, postgresUrl)
		if err := postgresdb.InitPostgresDb(postgresDb.ConnectUrl); err != nil {
			return nil, err
		}
		Db = postgresDb
	} else {
		boltdb, err := boltdb.NewBoltDb(pathToDb)
		if err != nil {
			return nil, err
		}

		Db = boltdb
	}
	return Db, nil
}
