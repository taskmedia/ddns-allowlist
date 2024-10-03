// Package ddns_whitelist usesthis implementation to log messages
// source: https://github.com/traefik/plugindemo/issues/22#issuecomment-2329608616
//
// Hint: does not support other log formats (e.g. json) than the default common
//
//revive:disable-next-line:var-naming
//nolint:stylecheck
package ddns_whitelist

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

const (
	// prefixDebug = "DBG"
	prefixInfo = "INF"
	// prefixError = "ERR"
)

// Logger will log messages with context.
type Logger struct {
	_info   func(args ...interface{})
	_debug  func(args ...interface{})
	_error  func(args ...interface{})
	_infof  func(format string, args ...interface{})
	_debugf func(format string, args ...interface{})
	_errorf func(format string, args ...interface{})
	context map[string]interface{}
}

// newLogger is used to log messages with context in Traefik log format.
func newLogger(_logLevel, middleware, middlewareType string) *Logger {
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
			prefixArgs := append([]interface{}{getTimestamp(), prefixInfo, ">"}, args...)
			log.New(os.Stdout, "", 0).Println(prefixArgs...)
		},
		_error: func(args ...interface{}) {
			log.Println(args...)
		},
		_debugf: func(format string, args ...interface{}) {
			fmt.Printf(format+"\n", args...)
		},
		_infof: func(format string, args ...interface{}) {
			f := getTimestamp() + " " + prefixInfo + " > " + format
			log.New(os.Stdout, "", 0).Printf(f, args...)
		},
		_errorf: func(format string, args ...interface{}) {
			log.Printf(format+"\n", args...)
		},
		context: map[string]interface{}{
			"middlewareName": middleware,
			"middlewareType": middlewareType,
		},
	}

	noopLog := func(_ ...interface{}) {}
	noopLogf := func(_ string, _ ...interface{}) {}

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

func getTimestamp() string {
	return time.Now().Format(time.RFC3339)
}

func (l *Logger) logWithContext(logFunc func(args ...interface{}), args ...interface{}) {
	if len(l.context) > 0 {
		contextStr := ""
		for k, v := range l.context {
			contextStr += fmt.Sprintf("%s=%v ", k, v)
		}
		args = append([]interface{}{contextStr}, args...)
	}
	logFunc(args...)
}

func (l *Logger) logWithContextf(logFunc func(format string, args ...interface{}), format string, args ...interface{}) {
	if len(l.context) > 0 {
		contextStr := ""
		for k, v := range l.context {
			contextStr += fmt.Sprintf("%s=%v ", k, v)
		}
		format = contextStr + format
	}
	logFunc(format, args...)
}

// Debug prints an debug log.
func (l *Logger) Debug(args ...interface{}) {
	l.logWithContext(l._debug, args...)
}

// Info prints an info log.
func (l *Logger) Info(args ...interface{}) {
	l.logWithContext(l._info, args...)
}

// Error prints an error log.
func (l *Logger) Error(args ...interface{}) {
	l.logWithContext(l._error, args...)
}

// Debugf prints an debug log.
func (l *Logger) Debugf(format string, args ...interface{}) {
	l.logWithContextf(l._debugf, format, args...)
}

// Infof prints an info log.
func (l *Logger) Infof(format string, args ...interface{}) {
	l.logWithContextf(l._infof, format, args...)
}

// Errorf prints an error log.
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.logWithContextf(l._errorf, format, args...)
}
