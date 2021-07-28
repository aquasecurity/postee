package dbservice

import (
	"errors"
	"os"
	"testing"

	"go.etcd.io/bbolt"
	bolt "go.etcd.io/bbolt"
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
	var tests = []struct {
		input *string
	}{
		{&AlpineImageResult},
	}

	dbPathReal := DbPath
	defer func() {
		os.Remove(DbPath)
		DbPath = dbPathReal
	}()
	DbPath = "test_webhooks.db"

	for _, test := range tests {

		// Handling of first scan
		isNew, err := MayBeStoreMessage([]byte(*test.input), AlpineImageKey)
		if err != nil {
			t.Errorf("Error: %s\n", err)
		}
		if !isNew {
			t.Errorf("A first scan was found!\n")
		}

		// Handling of second scan with the same data
		isNew, err = MayBeStoreMessage([]byte(*test.input), AlpineImageKey)
		if err != nil {
			t.Errorf("Error: %s\n", err)
		}
		if isNew {
			t.Errorf("A old scan wasn't found!\n")
		}
	}

}
func TestInitError(t *testing.T) {
	originalInit := Init
	originalDbPath := DbPath
	initErr := errors.New("init error")

	DbPath = "test_webhooks.db"

	Init = func(db *bbolt.DB, bucket string) error {
		return initErr
	}

	defer func() {
		Init = originalInit
		os.Remove(DbPath)
		DbPath = originalDbPath
	}()
	isNew, err := MayBeStoreMessage([]byte(AlpineImageResult), AlpineImageKey)

	if isNew {
		t.Errorf("Scan shouldn't be marked as new\n")
	}

	if err != initErr {
		t.Errorf("Unexpected error: expected %s, got %s \n", initErr, err)
	}

}
func TestSelectError(t *testing.T) {
	originalDbSelect := dbSelect
	originalDbPath := DbPath
	selectErr := errors.New("select error")

	DbPath = "test_webhooks.db"

	dbSelect = func(db *bolt.DB, bucket, key string) (result []byte, err error) {
		return nil, selectErr
	}

	defer func() {
		dbSelect = originalDbSelect
		os.Remove(DbPath)
		DbPath = originalDbPath
	}()
	isNew, err := MayBeStoreMessage([]byte(AlpineImageResult), AlpineImageKey)

	if isNew {
		t.Errorf("Scan shouldn't be marked as new\n")
	}

	if err != selectErr {
		t.Errorf("Unexpected error: expected %s, got %s \n", selectErr, err)
	}

}
func TestInsertError(t *testing.T) {
	var tests = []struct {
		bucket string
	}{
		{"WebhookBucket"},
		{"WebookExpiryDates"},
	}
	for _, test := range tests {
		testBucketInsert(t, test.bucket)
	}
}

func testBucketInsert(t *testing.T, testBucket string) {
	originalDbInsert := dbInsert
	originalDbPath := DbPath
	insertErr := errors.New("insert error")

	DbPath = "test_webhooks.db"

	dbInsert = func(db *bolt.DB, bucket string, key, value []byte) error {
		if bucket == testBucket {
			return insertErr
		}
		return nil
	}

	defer func() {
		dbInsert = originalDbInsert
		os.Remove(DbPath)
		DbPath = originalDbPath
	}()

	isNew, err := MayBeStoreMessage([]byte(AlpineImageResult), AlpineImageKey)

	if isNew {
		t.Errorf("Scan shouldn't be marked as new\n")
	}

	if err != insertErr {
		t.Errorf("Unexpected error: expected %s, got %s \n", insertErr, err)
	}
}
