package dbservice

import (
	"sync"
	"time"
)

const (
	dbBucketName       = "WebhookBucket"
	dbBucketAggregator = "WebhookAggregator"
	dbBucketExpiryDates= "WebookExpiryDates"
)

var (
	DbSizeLimit = 0
	DbDueDate   = 0
	dueTimeBase = time.Hour*time.Duration(24)

	DbPath = "/server/database/webhooks.db"
	mutex   sync.Mutex
)