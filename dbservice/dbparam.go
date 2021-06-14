package dbservice

import (
	"log"
	"path/filepath"
	"sync"
	"time"
)

var (
	dbBucketName        = "WebhookBucket"
	dbBucketAggregator  = "WebhookAggregator"
	dbBucketExpiryDates = "WebookExpiryDates"

	DbSizeLimit = 0
	DbDueDate   = 0
	dueTimeBase = time.Hour * time.Duration(24)

	DbPath = "/server/database/webhooks.db"
	mutex  sync.Mutex
)

func ChangeDbPath(newPath string) {
	mutex.Lock()
	DbPath = newPath
	mutex.Unlock()
}

func GetAbsDbPath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		log.Println(err)
		// on error, fall back to the supplied path
		return path
	}
	return absPath
}
