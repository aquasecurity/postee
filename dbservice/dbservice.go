package dbservice

import (
	"os"
	"time"

	"github.com/aquasecurity/postee/dbservice/boltdb"
	"github.com/aquasecurity/postee/dbservice/postgresdb"
)

var (
	Db DbProvider
)

type DbSettings struct {
	DBMaxSize       int `json:"max-db-size,omitempty"`
	DBRemoveOldData int `json:"delete-old-data,omitempty"`
	DBTestInterval  int `json:"db-verify-interval,omitempty"`

	//PostgresDb
	DbName     string `json:"dbname,omitempty"`
	DbHostName string `json:"dbhostname,omitempty"`
	DbPort     string `json:"dbport,omitempty"`
	DbUser     string `json:"dbuser,omitempty"`
	DbPassword string `json:"dbpassword,omitempty"`
	DbSslMode  string `json:"dbsslmode,omitempty"`

	//BoltDb
	DbPath string `json:"dbpath,omitempty"`
}
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

func ConfigureDb(settings *DbSettings, id string) error {
	if settings.DBTestInterval == 0 {
		settings.DBTestInterval = 1
	}

	if settings.DbName == "" && settings.DbHostName == "" && settings.DbUser == "" {
		boltdb := boltdb.NewBoltDb()
		if os.Getenv("PATH_TO_DB") != "" {
			boltdb.SetNewDbPathFromEnv()
		}
		Db = boltdb
		return nil
	} else {
		db, err := postgresdb.NewPostgresDb(id, settings.DbName, settings.DbHostName, settings.DbPort, settings.DbUser, settings.DbPassword, settings.DbSslMode)
		if err != nil {
			return err
		}
		if err = db.TestConnect(); err != nil {
			return err
		}
		Db = db
	}
	Db.SetDbSizeLimit(settings.DBMaxSize)
	return nil
}
