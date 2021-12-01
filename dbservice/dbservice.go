package dbservice

import (
	"errors"
	"os"
	"time"

	"github.com/aquasecurity/postee/dbservice/boltdb"
	"github.com/aquasecurity/postee/dbservice/postgresdb"
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
	SetDbSizeLimit(limit int)
}

func ConfigurateDb(id string, dBTestInterval *int, dbMaxSize int) error {
	if *dBTestInterval == 0 {
		*dBTestInterval = 1
	}

	if os.Getenv("POSTGRES_URL") != "" {
		if id == "" {
			return errors.New("error configurate postgresDb: 'id' is empty")
		}
		postgresDb := postgresdb.NewPostgresDb(id, os.Getenv("POSTGRES_URL"))
		if err := postgresdb.TestConnect(postgresDb.ConnectUrl); err != nil {
			return err
		}
		Db = postgresDb
	} else {
		boltdb := boltdb.NewBoltDb()
		if os.Getenv("PATH_TO_BOLTDB") != "" {
			if err := boltdb.SetNewDbPathFromEnv(); err != nil {
				return err
			}
		}
		Db = boltdb
	}
	Db.SetDbSizeLimit(dbMaxSize)
	return nil
}
