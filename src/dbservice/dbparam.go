package dbservice

import "sync"

const (
	dbBucketName       = "WebhookBucket"
	dbBucketAggregator = "WebhookAggregator"
)

var (
	DbPath = "webhooks.db"
	mutex   sync.Mutex
)
