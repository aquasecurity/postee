package boltdb

import (
	"os"
	"testing"
)

func TestApiKey(t *testing.T) {
	db := NewBoltDb()
	dbPathReal := db.DbPath
	defer func() {
		os.Remove(db.DbPath)
		db.DbPath = dbPathReal
	}()
	db.DbPath = "test_webhooks.db"
	db.EnsureApiKey()
	key, err := db.GetApiKey()
	if err != nil {
		t.Fatal("error while getting value of API key")
	}
	if key == "" {
		t.Fatal("empty key received")
	}
}
func TestApiKeyWithoutInit(t *testing.T) {
	db := NewBoltDb()
	dbPathReal := db.DbPath
	defer func() {
		os.Remove(db.DbPath)
		db.DbPath = dbPathReal
	}()
	db.DbPath = "test_webhooks.db"
	key, err := db.GetApiKey()
	if err == nil {
		t.Fatal("Error is expected")
	}
	if key != "" {
		t.Fatal("Empty key is expected")
	}
}
func TestApiKeyRenewal(t *testing.T) {
	db := NewBoltDb()
	dbPathReal := db.DbPath
	defer func() {
		os.Remove(db.DbPath)
		db.DbPath = dbPathReal
	}()
	db.DbPath = "test_webhooks.db"
	var keys [2]string
	for i := 0; i < 2; i++ {
		db.EnsureApiKey()
		key, err := db.GetApiKey()
		if err != nil {
			t.Fatal("error while getting value of API key")
		}
		if key == "" {
			t.Fatal("empty key received")
		}
		keys[i] = key

	}
	if keys[0] == keys[1] {
		t.Errorf("Key is not updated. (before: %s and after update: %s)", keys[0], keys[1])
	}
}
