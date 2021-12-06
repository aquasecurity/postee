package postgresdb

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
