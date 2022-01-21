package dbservice

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetNewDbPathFromEnv(t *testing.T) {
	envPathToDbOld := os.Getenv("PATH_TO_DB")
	defer os.Setenv("PATH_TO_DB", envPathToDbOld)
	dbPathOld := DbPath

	defaultDbPath := "/server/database/webhooks.db"
	var tests = []struct {
		name             string
		envPathToDb      string
		changePermission bool
		expectedDBPath   string
	}{
		{"Empty PATH_TO_DB", "", false, defaultDbPath},
		{"Permission denied to create directory(default DbPath is used)", "/database/database.db", false, defaultDbPath},
		{"New DbPath", "./base/base.db", false, "./base/base.db"},
		{"Permission denied to check directory(default DbPath is used)", "webhook/database/webhooks.db", true, defaultDbPath},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			os.Setenv("PATH_TO_DB", test.envPathToDb)
			baseDir := strings.Split(filepath.Dir(test.envPathToDb), "/")[0]
			if test.changePermission {
				err := os.Mkdir(baseDir, os.ModeDir)
				if err != nil {
					t.Errorf("Can't create dir: %s", baseDir)
				}
				err = os.Chmod(baseDir, 0)
				if err != nil {
					t.Errorf("Can't change the mode dir in %s: %s", baseDir, err)
				}
			}
			SetNewDbPathFromEnv()
			defer os.RemoveAll(baseDir)
			defer ChangeDbPath(dbPathOld)

			if test.expectedDBPath != DbPath {
				t.Errorf("[%s] Paths is not equals, expected: %s, got: %s", test.name, test.expectedDBPath, DbPath)
			}

		})
	}
}
