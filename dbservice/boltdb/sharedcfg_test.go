package boltdb

import (
	"os"
	"testing"
)

func TestApiKey(t *testing.T) {
	path := "test_webhooks.db"
	db, _ := NewBoltDb(path)
	defer db.Close()
	defer func() {
		os.Remove(path)
	}()

	err := db.EnsureApiKey()
	if err != nil {
		t.Fatal("error EnsureApiKey")
	}
	key, err := db.GetApiKey()
	if err != nil {
		t.Fatal("error while getting value of API key")
	}
	if key == "" {
		t.Fatal("empty key received")
	}
}
func TestApiKeyWithoutInit(t *testing.T) {
	path := "test_webhooks.db"
	db, _ := NewBoltDb(path)
	defer db.Close()
	defer func() {
		os.Remove(path)
	}()

	key, err := db.GetApiKey()
	if err == nil {
		t.Fatal("Error is expected")
	}
	if key != "" {
		t.Fatal("Empty key is expected")
	}
}
func TestApiKeyRenewal(t *testing.T) {
	path := "test_webhooks.db"
	db, _ := NewBoltDb(path)
	defer db.Close()
	defer func() {
		os.Remove(path)
	}()

	var keys [2]string
	for i := 0; i < 2; i++ {
		err := db.EnsureApiKey()
		if err != nil {
			t.Errorf("error EnsureApiKey: %s", err)
		}
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
