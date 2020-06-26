package dbservice

import (
	"sync"
	"time"
)

var (
	dbBucketName       = "WebhookBucket"
	dbBucketAggregator = "WebhookAggregator"
	dbBucketExpiryDates= "WebookExpiryDates"

	DbSizeLimit = 0
	DbDueDate   = 0
	dueTimeBase = time.Hour*time.Duration(24)

	DbPath = "/server/database/webhooks.db"
	mutex   sync.Mutex
)