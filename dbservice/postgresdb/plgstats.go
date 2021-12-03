package postgresdb

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

func (postgresDb *PostgresDb) RegisterPlgnInvctn(name string) error {
	db, err := psqlConnect(postgresDb.ConnectUrl)
	if err != nil {
		return err
	}
	defer db.Close()

	amount := 0
	err = db.Get(&amount, fmt.Sprintf("SELECT %s FROM %s WHERE (%s=$1 AND %s=$2)", "amount", dbTableOutputStats, "id", "outputName"), postgresDb.Id, name)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	amount += 1
	err = insertOutputStats(db, postgresDb.Id, name, amount)
	if err != nil {
		return err
	}

	return nil
}
