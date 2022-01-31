package boltdb

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/aquasecurity/postee/log"
	bolt "go.etcd.io/bbolt"
)

const (
	DEFAULT_PATH = "/server/database/webhooks.db"
)

type BoltDb struct {
	mu     sync.Mutex
	DbPath string
	db     *bolt.DB
}

func NewBoltDb(paths ...string) (*BoltDb, error) {
	dbPath := DEFAULT_PATH
	if len(paths) > 0 {
		if paths[0] != "" {
			dbPath = paths[0]
		}
	}

	log.Logger.Infof("Open Bolt DB at %s", dbPath)
	dbConn, err := open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open bolt DB file: (%s) %w", dbPath, err)
	}

	return &BoltDb{
		db:     dbConn,
		DbPath: dbPath,
	}, nil
}

func open(path string) (*bolt.DB, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err = os.MkdirAll(filepath.Dir(path), os.ModePerm)
		if err != nil {
			return nil, err
		}
	}

	return bolt.Open(path, 0666, nil)
}

func (boltDb *BoltDb) ChangeDbPath(newPath string) error {
	boltDb.mu.Lock()
	defer boltDb.mu.Unlock()
	boltDb.DbPath = newPath

	if boltDb.db != nil {
		boltDb.db.Close()
	}

	dbConn, err := bolt.Open(newPath, 0666, nil)
	if err != nil {
		return fmt.Errorf("failed to open bolt DB file: (%s) %w", newPath, err)
	}

	boltDb.db = dbConn
	return nil
}

func (boltDb *BoltDb) Close() error {
	boltDb.mu.Lock()
	defer boltDb.mu.Unlock()
	return boltDb.db.Close()
}
