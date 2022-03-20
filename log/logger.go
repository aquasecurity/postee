package log

import (
	"log"
	"os"

	"github.com/aquasecurity/postee/v2/log/zaplogger"
)

var Logger LoggerType = NewWrapper(initDefaultLogger())

type LoggerType interface {
	Info(args ...interface{})
	Error(args ...interface{})
	Infof(template string, args ...interface{})
	Errorf(template string, args ...interface{})
	Warn(args ...interface{})
	Warnf(template string, args ...interface{})
	Debug(args ...interface{})
	Debugf(template string, args ...interface{})
	Fatal(args ...interface{})
	Fatalf(template string, args ...interface{})
}

func initDefaultLogger() LoggerType {
	debug := false
	disable := false

	if os.Getenv("POSTEE_DEBUG") != "" || os.Getenv("AQUAALERT_DEBUG") != "" {
		debug = true
	}

	if os.Getenv("POSTEE_QUIET") != "" {
		disable = true
	}

	logger, err := zaplogger.NewLogger(debug, disable)
	if err != nil {
		log.Fatalf("failed to initialize a logger: %v", err)
	}
	return logger
}

func SetLogger(logger LoggerType) {
	Logger = NewWrapper(logger)
}

func maybeTruncateArguments(v ...interface{}) {
	maxLen := 20
	for idx, e := range v {
		b, ok := e.([]byte)
		if ok {
			if l := len(b); l > maxLen {
				v[idx] = string(b[:maxLen])
			}
		}
	}
}

func PrnInputError(msg string, v ...interface{}) {
	maybeTruncateArguments(v...)
	Logger.Errorf(msg, v...)
}

func PrnInputInfo(msg string, v ...interface{}) {
	maybeTruncateArguments(v...)
	Logger.Infof(msg, v...)
}
