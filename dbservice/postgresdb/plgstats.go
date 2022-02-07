package postgresdb

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/aquasecurity/postee/v2/dbservice/dbparam"
	_ "github.com/lib/pq"
)

func (postgresDb *PostgresDb) RegisterPlgnInvctn(name string) error {
	db, err := psqlConnect(postgresDb.ConnectUrl)
	if err != nil {
		return err
	}

	amount := 0
	sqlQuery := fmt.Sprintf("SELECT %s FROM %s WHERE (tenantName=$1 AND %s=$2)", "amount", dbparam.DbBucketOutputStats, "outputName")
	err = db.Get(&amount, sqlQuery, postgresDb.TenantName, name)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	amount += 1
	err = insertOutputStats(db, postgresDb.TenantName, name, amount)
	if err != nil {
		return err
	}
	return nil
}
