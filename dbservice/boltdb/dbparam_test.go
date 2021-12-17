package boltdb

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetNewDbPathFromEnv(t *testing.T) {
	db := NewBoltDb()
	dbPathOld := db.DbPath

	defaultDbPath := "/server/database/webhooks.db"
	var tests = []struct {
		name             string
		pathToDb         string
		changePermission bool
		expectedDBPath   string
		expectedErr      error
	}{
		{"Empty pathToDb", "", false, defaultDbPath, nil},
		{"Permission denied to create directory(default DbPath is used)", "/database/database.db", false, defaultDbPath, errors.New("mkdir /database: permission denied")},
		{"New DbPath", "./base/base.db", false, "./base/base.db", nil},
		{"Permission denied to check directory(default DbPath is used)", "webhook/database/webhooks.db", true, defaultDbPath, errors.New("stat webhook/database/webhooks.db: permission denied")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			baseDir := strings.Split(filepath.Dir(test.pathToDb), "/")[0]
			if test.changePermission {
				err := os.Mkdir(baseDir, os.ModeDir)
				if err != nil {
					t.Errorf("Can't create dir: %s", baseDir)
				}
				if err := os.Chmod(baseDir, 0); err != nil {
					t.Errorf("Can't change the mode dir in %s: %s", baseDir, err)
				}
			}
			if err := db.SetNewDbPath(test.pathToDb); err != nil && errors.Is(err, test.expectedErr) {
				t.Errorf("unexpected error setNewDbPath, expected: %v, got: %v", test.expectedErr, err)
			}
			defer os.RemoveAll(baseDir)
			defer db.ChangeDbPath(dbPathOld)

			if test.expectedDBPath != db.DbPath {
				t.Errorf("[%s] Paths is not equals, expected: %s, got: %s", test.name, test.expectedDBPath, db.DbPath)
			}

		})
	}
}
