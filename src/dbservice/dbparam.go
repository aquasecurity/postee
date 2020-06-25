package dbservice

import "sync"

const (
	dbBucketName       = "WebhookBucket"
	dbBucketAggregator = "WebhookAggregator"
)

var (
	DbPath = "/server/database/webhooks.db"
	mutex   sync.Mutex
)
