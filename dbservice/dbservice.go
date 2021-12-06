package dbservice

import (
	"errors"
	"time"

	"github.com/aquasecurity/postee/dbservice/boltdb"
	"github.com/aquasecurity/postee/dbservice/dbparam"
	"github.com/aquasecurity/postee/dbservice/postgresdb"
	"github.com/aquasecurity/postee/utils"
)

var (
	Db DbProvider
)

type DbProvider interface {
	MayBeStoreMessage(message []byte, messageKey string, expired *time.Time) (wasStored bool, err error)
	CheckSizeLimit()
	CheckExpiredData()
	AggregateScans(output string, currentScan map[string]string, scansPerTicket int, ignoreTheQuantity bool) ([]map[string]string, error)
	RegisterPlgnInvctn(name string) error
	EnsureApiKey() error
	GetApiKey() (string, error)
}

func ConfigureDb(pathToDb, postgresUrl, tenantId string, dBTestInterval *int, dbMaxSize int) error {
	if *dBTestInterval == 0 {
		*dBTestInterval = 1
	}

	postgresUrl = utils.GetEnvironmentVarOrPlain(postgresUrl)
	pathToDb = utils.GetEnvironmentVarOrPlain(pathToDb)

	if postgresUrl != "" {
		if tenantId == "" {
			return errors.New("error configurate postgresDb: 'tenantId' is empty")
		}
		postgresDb := postgresdb.NewPostgresDb(tenantId, postgresUrl)
		if err := postgresdb.InitPostgresDb(postgresDb.ConnectUrl); err != nil {
			return err
		}
		Db = postgresDb
	} else {
		boltdb := boltdb.NewBoltDb()
		if pathToDb != "" {
			if err := boltdb.SetNewDbPath(pathToDb); err != nil {
				return err
			}
		}
		Db = boltdb
	}
	dbparam.DbSizeLimit = dbMaxSize
	return nil
}
