package boltdb

import (
	"errors"
	"os"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

var (
	AlpineImageKey    = "sha256:c8bccc0af9571ec0d006a43acb5a8d08c4ce42b6cc7194dd6eb167976f501ef1-alpine:3.8-Docker Hub"
	AlpineImageResult = `{
		"image": "alpine:3.8",
		"registry": "Docker Hub",
		"digest": "sha256:c8bccc0af9571ec0d006a43acb5a8d08c4ce42b6cc7194dd6eb167976f501ef1",
		"previous_digest": "sha256:c8bccc0af9571ec0d006a43acb5a8d08c4ce42b6cc7194dd6eb167976f501ef1",
		"image_assurance_results": {
			"disallowed": true,
			"checks_performed": [
				{
					"control": "max_severity",
					"policy_name": "Default",
					"failed": false
				},
				{
					"control": "trusted_base_images",
					"policy_name": "Default",
					"failed": true
				},
				{
					"control": "max_score",
					"policy_name": "Default",
					"failed": false
				}
			]
		},
		"vulnerability_summary": {
			"total": 2,
			"critical": 0,
			"high": 0,
			"medium": 2,
			"low": 0,
			"negligible": 0,
			"sensitive": 0,
			"malware": 0
		},
		"scan_options": {
			"scan_sensitive_data": true,
			"scan_malware": true
		},
		"resources": [
			{
				"vulnerabilities": [
					{
						"name": "CVE-2018-20679",
						"version": "",
						"fix_version": "",
						"aqua_severity": "medium"
					},
					{
						"name": "CVE-2019-5747",
						"version": "",
						"fix_version": "",
						"aqua_severity": "medium"
					}
				],
				"resource": {
					"name": "busybox",
					"version": "1.28.4-r3"
				}
			}
		]
	}`
)

func TestStoreMessage(t *testing.T) {
	path := "test_webhooks.db"
	db, _ := NewBoltDb(path)
	defer db.Close()
	var tests = []struct {
		input *string
	}{
		{&AlpineImageResult},
	}

	defer func() {
		os.Remove(path)
	}()

	for _, test := range tests {

		// Handling of first scan
		isNew, err := db.MayBeStoreMessage([]byte(*test.input), AlpineImageKey, nil)
		if err != nil {
			t.Errorf("Error: %s\n", err)
		}
		if !isNew {
			t.Errorf("A first scan was found!\n")
		}

		// Handling of second scan with the same data
		isNew, err = db.MayBeStoreMessage([]byte(*test.input), AlpineImageKey, nil)
		if err != nil {
			t.Errorf("Error: %s\n", err)
		}
		if isNew {
			t.Errorf("A old scan wasn't found!\n")
		}
	}

}
func TestInitError(t *testing.T) {
	path := "test_webhooks.db"
	db, _ := NewBoltDb(path)
	defer db.Close()
	originalInit := Init
	initErr := errors.New("init error")

	Init = func(db *bbolt.DB, bucket string) error {
		return initErr
	}

	defer func() {
		Init = originalInit
		os.Remove(path)
	}()
	isNew, err := db.MayBeStoreMessage([]byte(AlpineImageResult), AlpineImageKey, nil)

	if isNew {
		t.Errorf("Scan shouldn't be marked as new\n")
	}

	if !errors.Is(err, initErr) {
		t.Errorf("Unexpected error: expected %s, got %s \n", initErr, err)
	}

}
func TestSelectError(t *testing.T) {
	path := "test_webhooks.db"
	db, _ := NewBoltDb(path)
	defer db.Close()

	originalDbSelect := dbSelect
	selectErr := errors.New("select error")

	dbSelect = func(db *bbolt.DB, bucket, key string) (result []byte, err error) {
		return nil, selectErr
	}

	defer func() {
		dbSelect = originalDbSelect
		os.Remove(path)
	}()
	isNew, err := db.MayBeStoreMessage([]byte(AlpineImageResult), AlpineImageKey, nil)

	if isNew {
		t.Errorf("Scan shouldn't be marked as new\n")
	}

	if !errors.Is(err, selectErr) {
		t.Errorf("Unexpected error: expected %s, got %s \n", selectErr, err)
	}

}
func TestInsertError(t *testing.T) {
	var tests = []struct {
		bucket string
	}{
		{"WebhookBucket"},
		{"WebhookExpiryDates"},
	}
	for _, test := range tests {
		testBucketInsert(t, test.bucket)
	}
}

func testBucketInsert(t *testing.T, testBucket string) {
	path := "test_webhooks.db"
	db, _ := NewBoltDb(path)
	defer db.Close()
	originalDbInsert := dbInsert
	insertErr := errors.New("insert error")

	dbInsert = func(db *bbolt.DB, bucket string, key, value []byte) error {
		if bucket == testBucket {
			return insertErr
		}
		return nil
	}

	defer func() {
		dbInsert = originalDbInsert
		os.Remove(path)
	}()
	//expired shouldn't be null to cause insert to 'WebhookExpiryDates' bucket
	timeToExpire := time.Duration(1) * time.Second
	expired := time.Now().UTC().Add(timeToExpire)

	isNew, err := db.MayBeStoreMessage([]byte(AlpineImageResult), AlpineImageKey, &expired)

	if isNew {
		t.Errorf("Scan shouldn't be marked as new\n")
	}

	if !errors.Is(err, insertErr) {
		t.Errorf("Unexpected error: expected %s, got %v \n", insertErr, err)
	}
}
