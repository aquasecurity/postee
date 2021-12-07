package boltdb

import (
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
	}{
		{"Empty pathToDb", "", false, defaultDbPath},
		{"Permission denied to create directory(default DbPath is used)", "/database/database.db", false, defaultDbPath},
		{"New DbPath", "./base/base.db", false, "./base/base.db"},
		{"Permission denied to check directory(default DbPath is used)", "webhook/database/webhooks.db", true, defaultDbPath},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			baseDir := strings.Split(filepath.Dir(test.pathToDb), "/")[0]
			if test.changePermission {
				err := os.Mkdir(baseDir, os.ModeDir)
				if err != nil {
					t.Errorf("Can't create dir: %s", baseDir)
				}
				os.Chmod(baseDir, 0)
			}
			db.SetNewDbPath(test.pathToDb)
			defer os.RemoveAll(baseDir)
			defer db.ChangeDbPath(dbPathOld)

			if test.expectedDBPath != db.DbPath {
				t.Errorf("[%s] Paths is not equals, expected: %s, got: %s", test.name, test.expectedDBPath, db.DbPath)
			}

		})
	}
}
