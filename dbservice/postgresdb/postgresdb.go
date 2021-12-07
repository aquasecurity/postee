package postgresdb

type PostgresDb struct {
	ConnectUrl string
	TenantName string
}

func NewPostgresDb(tenantName, connectUrl string) *PostgresDb {
	return &PostgresDb{
		ConnectUrl: connectUrl,
		TenantName: tenantName,
	}
}
