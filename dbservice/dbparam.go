package dbservice

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
	dbBucketExpiryDates  = "WebookExpiryDates"
	DbBucketOutputStats  = "WebhookOutputStats"
	DbBucketSharedConfig = "WebhookSharedConfig"

	DbSizeLimit = 0
	dueTimeBase = time.Hour * time.Duration(24)
	DateFmt     = time.RFC3339Nano

	DbPath = "/server/database/webhooks.db"
	mutex  sync.Mutex
)

func ChangeDbPath(newPath string) {
	mutex.Lock()
	DbPath = newPath
	mutex.Unlock()
}

func SetNewDbPathFromEnv() {
	newPath := os.Getenv("PATH_TO_DB")
	if _, err := os.Stat(newPath); err != nil {
		if os.IsNotExist(err) {
			err = os.MkdirAll(filepath.Dir(newPath), os.ModePerm)
			if err != nil {
				log.Printf("Can't create DateBase directory: %v", err)
			}
		}
	}
	ChangeDbPath(newPath)
}
