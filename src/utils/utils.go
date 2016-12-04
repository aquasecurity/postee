package utils

import (
	"errors"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
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

func Daemonize() error {
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigs
		log.Println(sig)
		done <- true
	}()

	<-done
	return nil
}

func GetRootDir() string {
	rootdir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	return rootdir
}

func PathExists(name string) bool {
	_, err := os.Stat(name)
	return !os.IsNotExist(err)
}

func GetEnv(name string) (string, error) {
	value := os.Getenv(name)
	if len(value) > 0 {
		return value, nil
	}
	return "", errors.New("not found")
}
