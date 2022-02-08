package utils

import (
	"errors"

	"os"
	"path/filepath"
	"strings"
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
