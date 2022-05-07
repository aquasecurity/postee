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
	DbBucketActionStats  = "WebhookActionStats"
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
		ChangeDbPath(newPath)
	}
}
