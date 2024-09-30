// source: https://github.com/traefik/plugindemo/issues/22#issuecomment-2329608616
package ddnswhitelist

import (
	"fmt"
	"log"
	"strings"
)

type Logger struct {
	_info   func(args ...interface{})
	_debug  func(args ...interface{})
	_error  func(args ...interface{})
	_infof  func(format string, args ...interface{})
	_debugf func(format string, args ...interface{})
	_errorf func(format string, args ...interface{})
}

func NewLogger(_logLevel string) *Logger {
	logLevel := strings.ToLower(_logLevel)
	// This globally sets the flags for the standard logger which is generally
	// a bad practice, however, since Traefik is capturing the output of the
	// logger and redirecting it to its own logger, this is the only way to
	// ensure that the error logs are not prefixed by the date and time, and
	// has no other side effects.
	log.SetFlags(0)

	logger := &Logger{
		_debug: func(args ...interface{}) {
			fmt.Println(args...)
		},
		_info: func(args ...interface{}) {
			fmt.Println(args...)
		},
		_error: func(args ...interface{}) {
			log.Println(args...)
		},
		_debugf: func(format string, args ...interface{}) {
			fmt.Printf(format+"\n", args...)
		},
		_infof: func(format string, args ...interface{}) {
			fmt.Printf(format+"\n", args...)
		},
		_errorf: func(format string, args ...interface{}) {
			log.Printf(format+"\n", args...)
		},
	}

	noopLog := func(args ...interface{}) {}
	noopLogf := func(format string, args ...interface{}) {}

	switch logLevel {
	default:
	case "error":
		logger._debug = noopLog
		logger._debugf = noopLogf
		logger._info = noopLog
		logger._infof = noopLogf
	case "info":
		logger._debug = noopLog
		logger._debugf = noopLogf
	case "debug":
		break
	}

	return logger
}

func (l *Logger) Debug(args ...interface{}) {
	l._debug(args...)
}

func (l *Logger) Info(args ...interface{}) {
	l._info(args...)
}

func (l *Logger) Error(args ...interface{}) {
	l._error(args...)
}

func (l *Logger) Debugf(format string, args ...interface{}) {
	l._debugf(format, args...)
}

func (l *Logger) Infof(format string, args ...interface{}) {
	l._infof(format, args...)
}

func (l *Logger) Errorf(format string, args ...interface{}) {
	l._errorf(format, args...)
}
