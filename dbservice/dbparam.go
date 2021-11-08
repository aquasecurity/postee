package dbservice

import (
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
