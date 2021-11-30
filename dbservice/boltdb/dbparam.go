package boltdb

import (
	"log"
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

func (boltDb *BoltDb) SetNewDbPathFromEnv() {
	newPath := os.Getenv("PATH_TO_DB")
	if newPath != "" {
		if _, err := os.Stat(newPath); err != nil {
			if os.IsNotExist(err) {
				err = os.MkdirAll(filepath.Dir(newPath), os.ModePerm)
				if err != nil {
					log.Printf("Can't create DateBase directory: %v, the default path is used", err)
					return
				}
			} else {
				log.Printf("Can't check DateBase directory: %v, the default path is used", err)
				return
			}
		}
		boltDb.ChangeDbPath(newPath)
	}
}

func (boltDb *BoltDb) SetDbSizeLimit(limit int) {
	DbSizeLimit = limit
}
