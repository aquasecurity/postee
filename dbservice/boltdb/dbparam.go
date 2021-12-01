package boltdb

import (
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	dbBucketName         = "WebhookBucket"
	dbBucketAggregator   = "WebhookAggregator"
	dbBucketExpiryDates  = "WebhookExpiryDates"
	dbBucketOutputStats  = "WebhookOutputStats"
	dbBucketSharedConfig = "WebhookSharedConfig"

	DbSizeLimit = 0
	DateFmt     = time.RFC3339Nano
	dueTimeBase = time.Hour * time.Duration(24)

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

func (boltDb *BoltDb) SetNewDbPathFromEnv() error {
	newPath := os.Getenv("PATH_TO_BOLTDB")
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

func (boltDb *BoltDb) SetDbSizeLimit(limit int) {
	DbSizeLimit = limit
}
