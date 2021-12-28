package log

import "github.com/aquasecurity/postee/log/stdoutlogger"

var Logger LoggerType = initDefaultLogger()

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
	return stdoutlogger.NewLogger()
}

func SetLogger(loggerType LoggerType) {
	Logger = loggerType
}
