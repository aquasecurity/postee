package utils

import (
	"errors"

	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/postee/log"
)

func GetEnvironmentVarOrPlain(value string) string {
	const VarPrefix = "$"
	if strings.HasPrefix(value, VarPrefix) {
		return os.Getenv(strings.TrimPrefix(value, VarPrefix))
	}
	return value
}

func GetEnv(name string) (string, error) {
	value := os.Getenv(name)
	if len(value) > 0 {
		return value, nil
	}
	return "", errors.New("not found")
}

// GetRootDir returns the full path of the directory in which the process
// is running.
func GetRootDir() (string, error) {
	return filepath.Abs(filepath.Dir(os.Args[0]))
}

// PathExists checks if a (full) path exists on the host/container.
func PathExists(name string) bool {
	_, err := os.Stat(name)
	return !os.IsNotExist(err)
}

func PrnInputLogs(msg string, v ...interface{}) {
	maxLen := 20
	for idx, e := range v {
		b, ok := e.([]byte)
		if ok {
			if l := len(b); l > maxLen {
				v[idx] = string(b[:maxLen])
			}
		}
	}
	log.Logger.Errorf(msg, v...)
}
