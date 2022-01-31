package postgresdb

func (postgresDb *PostgresDb) Close() error {
	db, err := psqlConnect(postgresDb.ConnectUrl)
	if err != nil {
		return err
	}

	return db.Close()
}
