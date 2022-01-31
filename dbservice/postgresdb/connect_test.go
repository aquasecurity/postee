package postgresdb

import (
	"errors"
	"testing"

	"github.com/jmoiron/sqlx"
)

func TestConnectFuncError(t *testing.T) {
	expectedError := "Error postgresDb test connect: connect error"
	savedpsqlConnect := psqlConnect
	defer func() {
		psqlConnect = savedpsqlConnect
	}()
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		return nil, errors.New("connect error")
	}
	_, err := testConnect("url")
	if err.Error() != expectedError {
		t.Errorf("error text connect, expectedError: %v, got: %v", expectedError, err)
	}
}
