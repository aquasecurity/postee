package stdoutlogger

import (
	"fmt"
	"log"
	"os"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorBlue   = "\033[34m"
	colorYellow = "\033[33m"
	colorPurple = "\033[35m"
	infoLevel   = colorBlue + "   [INFO]   " + colorReset
	warnLevel   = colorYellow + "   [WARN]   " + colorReset
	errorLevel  = colorRed + "   [ERROR]   " + colorReset
	debugLevel  = colorPurple + "   [DEBUG]   " + colorReset
	fatalLevel  = colorRed + "   [FATAL]   " + colorReset
)

type StdOutLogger struct {
	logger log.Logger
}

func NewLogger() StdOutLogger {
	logger := log.New(os.Stdout, "", log.Ldate|log.Ltime)
	return StdOutLogger{logger: *logger}
}

func (stdOutLogger StdOutLogger) Info(args ...interface{}) {
	stdOutLogger.logger.Print(infoLevel + getMessage("", args))
}

func (stdOutLogger StdOutLogger) Error(args ...interface{}) {
	stdOutLogger.logger.Print(errorLevel + getMessage("", args))
}

func (stdOutLogger StdOutLogger) Warn(args ...interface{}) {
	stdOutLogger.logger.Print(warnLevel + getMessage("", args))
}
func (stdOutLogger StdOutLogger) Debug(args ...interface{}) {
	stdOutLogger.logger.Print(debugLevel + getMessage("", args))
}

func (stdOutLogger StdOutLogger) Fatal(args ...interface{}) {
	stdOutLogger.logger.Fatal(fatalLevel + getMessage("", args))
}

func (stdOutLogger StdOutLogger) Infof(template string, args ...interface{}) {
	stdOutLogger.logger.Print(infoLevel + getMessage(template, args))
}

func (stdOutLogger StdOutLogger) Errorf(template string, args ...interface{}) {
	stdOutLogger.logger.Print(errorLevel + getMessage(template, args))
}

func (stdOutLogger StdOutLogger) Warnf(template string, args ...interface{}) {
	stdOutLogger.logger.Print(warnLevel + getMessage(template, args))
}

func (stdOutLogger StdOutLogger) Debugf(template string, args ...interface{}) {
	stdOutLogger.logger.Print(debugLevel + getMessage(template, args))
}

func (stdOutLogger StdOutLogger) Fatalf(template string, args ...interface{}) {
	stdOutLogger.logger.Fatal(fatalLevel + getMessage(template, args))
}

func getMessage(template string, fmtArgs []interface{}) string {
	if len(fmtArgs) == 0 {
		return template
	}

	if template != "" {
		return fmt.Sprintf(template, fmtArgs...)
	}

	if len(fmtArgs) == 1 {
		if str, ok := fmtArgs[0].(string); ok {
			return str
		}
	}
	return fmt.Sprint(fmtArgs...)
}
