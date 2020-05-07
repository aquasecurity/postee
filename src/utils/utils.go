package utils

import (
	"errors"
	"log"
	"os"
)

var (
	dbg = false
)

func InitDebug() {
	if os.Getenv("AQUAALERT_DEBUG") != "" {
		dbg = true
	}
}

func Debug(format string, v ...interface{}) {
	if dbg != false {
		log.Printf(format, v...)
	}
}

func GetEnv(name string) (string, error) {
	value := os.Getenv(name)
	if len(value) > 0 {
		return value, nil
	}
	return "", errors.New("not found")
}
