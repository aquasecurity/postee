package boltdb

import (
	"os"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestConfigureBoltDb(t *testing.T) {
	tests := []struct {
		name         string
		dbPath       string
		expectedPath string
	}{
		{"happy configuration BoltDB with dbPath", "database/webhooks.db", "database/webhooks.db"},
		{"happy configuration BoltDB with empty dbPath", "", "/server/database/webhooks.db"},
	}

	savedOpen := open

	open = func(path string) (*bolt.DB, error) {
		return nil, nil
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			boltdb, err := NewBoltDb(test.dbPath)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			configuredPath := boltdb.DbPath

			if test.expectedPath != configuredPath {
				t.Errorf("paths do not match, expected: %s, got: %s", test.expectedPath, configuredPath)
			}
		})
	}
	defer func() {
		os.RemoveAll("database/")
		open = savedOpen
	}()
}
