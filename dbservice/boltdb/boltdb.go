package boltdb

import (
	"os"
	"path/filepath"
	"sync"
)

var (
	mutex sync.Mutex
)

type BoltDb struct {
	DbPath string
}

func NewBoltDb() *BoltDb {
	return &BoltDb{
		DbPath: "/server/database/webhooks.db",
	}
}

func (boltDb *BoltDb) ChangeDbPath(newPath string) {
	mutex.Lock()
	boltDb.DbPath = newPath
	mutex.Unlock()
}

func (boltDb *BoltDb) SetNewDbPath(newPath string) error {
	if newPath != "" {
		if _, err := os.Stat(newPath); err != nil {
			if os.IsNotExist(err) {
				err = os.MkdirAll(filepath.Dir(newPath), os.ModePerm)
				if err != nil {
					return err
				}
			} else {
				return err
			}
		}
		boltDb.ChangeDbPath(newPath)
	}
	return nil
}

// unimplemented
func (boltDb *BoltDb) Close() error {
	return nil
}
