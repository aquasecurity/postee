package postgresdb

import (
	"errors"
	"log"
	"strings"
	"time"

	"github.com/aquasecurity/postee/utils"
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
	psqlInfo string
	id       string
}

func NewPostgresDb(id, dbName, dbHostName, dbPort, dbUser, dbPassword, dbSslMode string) (*PostgresDb, error) {
	info, err := buildPsqlInfo(dbName, dbHostName, dbPort, dbUser, dbPassword, dbSslMode)
	if err != nil {
		return nil, err
	}
	return &PostgresDb{
		psqlInfo: info,
		id:       id,
	}, nil
}

func buildPsqlInfo(dbName, dbHostName, dbPort, dbUser, dbPassword, dbSslMode string) (string, error) {
	psqlInfo := []string{}

	if dbHostName != "" {
		dbHostName = utils.GetEnvironmentVarOrPlain(dbHostName)
		psqlInfo = append(psqlInfo, "host="+dbHostName)
	} else {
		log.Printf("dbHostName is empty, for psqlInfo is used dbHostName=localhost")
	}
	if dbPort != "" {
		dbPort = utils.GetEnvironmentVarOrPlain(dbPort)
		psqlInfo = append(psqlInfo, "port="+dbPort)
	} else {
		log.Printf("dbPort is empty, for psqlInfo is used dbPort=5432")
	}
	if dbName != "" {
		dbName = utils.GetEnvironmentVarOrPlain(dbName)
		psqlInfo = append(psqlInfo, "dbname="+dbName)
	} else {
		return "", errors.New("can't build psqlInfo, dbName is empty")
	}
	if dbUser != "" {
		dbUser = utils.GetEnvironmentVarOrPlain(dbUser)
		psqlInfo = append(psqlInfo, "user="+dbUser)
	} else {
		return "", errors.New("can't build psqlInfo, dbUser is empty")
	}
	if dbPassword != "" {
		dbPassword = utils.GetEnvironmentVarOrPlain(dbPassword)
		psqlInfo = append(psqlInfo, "password="+dbPassword)
	}
	if dbSslMode != "" {
		psqlInfo = append(psqlInfo, "sslmode="+dbSslMode)
	} else {
		log.Printf("dbSslMode is empty, for psqlInfo is used sslmode=disable")
		psqlInfo = append(psqlInfo, "sslmode="+"disable")
	}
	return strings.Join(psqlInfo[:], " "), nil
}

func (postgresDb *PostgresDb) SetDbSizeLimit(limit int) {
	DbSizeLimit = limit
}

func (postgresDb *PostgresDb) TestConnect() error {
	_, err := psqlConnect(postgresDb.psqlInfo)
	return errors.New("Error postgresDb test connect: " + err.Error())
}

var psqlConnect = func(psqlInfo string) (*sqlx.DB, error) {
	db, err := sqlx.Connect("postgres", psqlInfo)
	if err != nil {
		return nil, err
	}
	return db, nil
}
