package dbparam

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"time"
)

var (
	DbBucketName          = "WebhookBucket"
	DbBucketAggregator    = "WebhookAggregator"
	DbBucketExpiryDates   = "WebhookExpiryDates"
	DbBucketOutputStats   = "WebhookOutputStats"
	DbBucketSharedConfig  = "WebhookSharedConfig"
	DbTableCfgCacheSource = "WebhookCfgCacheSource"

	DbSizeLimit = 0
	DateFmt     = time.RFC3339Nano
	DueTimeBase = time.Hour * time.Duration(24)
)

func GenerateApiKey(length int) (string, error) {
	k := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return "", err
	}
	return hex.EncodeToString(k), nil
}
