package boltdb

import (
	"testing"
)

func TestChangeDbPath(t *testing.T) {
	boltDb, err := NewBoltDb()
	if err != nil {
		t.Fatal(err)
	}

	defer boltDb.Close()
	testPath := "/tmp/test.db"
	storedPath := boltDb.DbPath
	_ = boltDb.ChangeDbPath(testPath)
	defer func() {
		_ = boltDb.ChangeDbPath(storedPath)
	}()
	if boltDb.DbPath != testPath {
		t.Errorf("path is not configured correctly, expected: %s, got %s", testPath, boltDb.DbPath)
	}
}
