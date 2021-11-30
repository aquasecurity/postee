package boltdb

import (
	"testing"
)

func TestChangeDbPath(t *testing.T) {
	boltDb := NewBoltDb()
	testPath := "/tmp/test.db"
	storedPath := boltDb.DbPath
	boltDb.ChangeDbPath(testPath)
	defer func() {
		boltDb.ChangeDbPath(storedPath)
	}()
	if boltDb.DbPath != testPath {
		t.Errorf("path is not configured correctly, expected: %s, got %s", testPath, boltDb.DbPath)
	}
}
