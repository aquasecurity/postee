package postgresdb

import (
	"errors"
	"testing"

	"github.com/jmoiron/sqlx"
)

func TestConnectFunc(t *testing.T) {
	expectedError := "Error postgresDb test connect: connect error"
	savedpsqlConnect := psqlConnect
	defer func() {
		psqlConnect = savedpsqlConnect
	}()
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		return nil, errors.New("connect error")
	}
	err := TestConnect("url")
	if err.Error() != expectedError {
		t.Errorf("error text connect, expectedError: %v, got: %v", expectedError, err)
	}
}
