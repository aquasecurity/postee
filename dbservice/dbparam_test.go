package dbservice

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSetNewDbPathFromEnv(t *testing.T) {
	var tests = []struct {
		env            string
		expectedDBPath string
	}{
		{"", "/server/database/webhooks.db"},
		{"/database/database.db", "/server/database/webhooks.db"},
		{"./base/base.db", "./base/base.db"},
	}
	envOld := os.Getenv("PATH_TO_DB")
	defer os.Setenv("PATH_TO_DB", envOld)

	for _, test := range tests {
		os.Setenv("PATH_TO_DB", test.env)
		SetNewDbPathFromEnv()

		if test.expectedDBPath != DbPath {
			t.Errorf("Paths is not equals, expected: %s, got: %s", test.expectedDBPath, DbPath)
		}
		os.RemoveAll(filepath.Dir(test.env))
	}
}
