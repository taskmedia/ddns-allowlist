// Package logger implementation to log messages
// source: https://github.com/traefik/plugindemo/issues/22#issuecomment-2329608616
//
// Hint: does not support other log formats (e.g. json) than the default common
package logger

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

const (
	prefixInfo  = colorGreen + "INF" + colorReset
	prefixTrace = colorBlue + "TRC" + colorReset
	delimiter   = colorCyan + ">" + colorReset
	colorReset  = "\033[0m"
	colorGray   = "\033[90m"
	colorGreen  = "\033[32m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
)

// Logger will log messages with context.
type Logger struct {
	_trace  func(args ...interface{})
	_debug  func(args ...interface{})
	_info   func(args ...interface{})
	_error  func(args ...interface{})
	_tracef func(format string, args ...interface{})
	_debugf func(format string, args ...interface{})
	_infof  func(format string, args ...interface{})
	_errorf func(format string, args ...interface{})
	context map[string]interface{}
}

// NewLogger is used to log messages with context in Traefik log format.
func NewLogger(_logLevel, middleware, middlewareType string) *Logger {
	logLevel := strings.TrimSpace(strings.ToLower(_logLevel))
	// This globally sets the flags for the standard logger which is generally
	// a bad practice, however, since Traefik is capturing the output of the
	// logger and redirecting it to its own logger, this is the only way to
	// ensure that the error logs are not prefixed by the date and time, and
	// has no other side effects.
	log.SetFlags(0)

	logger := createLogger(middleware, middlewareType)
	applyLogLevel(logger, logLevel)
	return logger
}

// createLogger creates a new logger instance with all logging functions enabled.
func createLogger(middleware, middlewareType string) *Logger {
	return &Logger{
		_trace:  createTraceFunc(),
		_debug:  createDebugFunc(),
		_info:   createInfoFunc(),
		_error:  createErrorFunc(),
		_tracef: createTracefFunc(),
		_debugf: createDebugfFunc(),
		_infof:  createInfofFunc(),
		_errorf: createErrorfFunc(),
		context: map[string]interface{}{
			"middlewareName": middleware,
			"middlewareType": middlewareType,
		},
	}
}

// applyLogLevel disables logging functions based on the specified log level.
func applyLogLevel(logger *Logger, logLevel string) {
	disableLog := func(_ ...interface{}) {}
	disableLogf := func(_ string, _ ...interface{}) {}

	// warning: yaegi interprets switch not as go (default, fallthrough)
	switch logLevel {
	case "error":
		// disable info logging
		logger._info = disableLog
		logger._infof = disableLogf
		fallthrough
	case "info":
		// disable debug logging
		logger._debug = disableLog
		logger._debugf = disableLogf
		fallthrough
	case "debug":
		// disable trace logging
		logger._trace = disableLog
		logger._tracef = disableLogf
	case "trace":
		// nothing disabled for most detailed logging
	default:
		// disable all logging except error
		logger._info = disableLog
		logger._infof = disableLogf
		logger._debug = disableLog
		logger._debugf = disableLogf
		logger._trace = disableLog
		logger._tracef = disableLogf
	}
}

// createTraceFunc creates the trace logging function.
func createTraceFunc() func(args ...interface{}) {
	return func(args ...interface{}) {
		prefixArgs := append([]interface{}{getTimestamp(), prefixTrace, delimiter}, args...)
		//nolint:errcheck
		fmt.Fprintln(os.Stdout, prefixArgs...)
	}
}

// createDebugFunc creates the debug logging function.
func createDebugFunc() func(args ...interface{}) {
	return func(args ...interface{}) {
		fmt.Println(args...)
	}
}

// createInfoFunc creates the info logging function.
func createInfoFunc() func(args ...interface{}) {
	return func(args ...interface{}) {
		prefixArgs := append([]interface{}{getTimestamp(), prefixInfo, delimiter}, args...)
		//nolint:errcheck
		fmt.Fprintln(os.Stdout, prefixArgs...)
	}
}

// createErrorFunc creates the error logging function.
func createErrorFunc() func(args ...interface{}) {
	return func(args ...interface{}) {
		log.Println(args...)
	}
}

// createTracefFunc creates the tracef logging function.
func createTracefFunc() func(format string, args ...interface{}) {
	return func(format string, args ...interface{}) {
		f := getTimestamp() + " " + prefixTrace + " " + delimiter + " " + format + "\n"
		//nolint:errcheck
		fmt.Fprintf(os.Stdout, f, args...)
	}
}

// createDebugfFunc creates the debugf logging function.
func createDebugfFunc() func(format string, args ...interface{}) {
	return func(format string, args ...interface{}) {
		fmt.Printf(format+"\n", args...)
	}
}

// createInfofFunc creates the infof logging function.
func createInfofFunc() func(format string, args ...interface{}) {
	return func(format string, args ...interface{}) {
		f := getTimestamp() + " " + prefixInfo + " " + delimiter + " " + format + "\n"
		//nolint:errcheck
		fmt.Fprintf(os.Stdout, f, args...)
	}
}

// createErrorfFunc creates the errorf logging function.
func createErrorfFunc() func(format string, args ...interface{}) {
	return func(format string, args ...interface{}) {
		log.Printf(format+"\n", args...)
	}
}

func getTimestamp() string {
	return colorGray + time.Now().Format(time.RFC3339) + colorReset
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

// Trace prints an debug log.
func (l *Logger) Trace(args ...interface{}) {
	l.logWithContext(l._trace, args...)
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

// Tracef prints an debug log.
func (l *Logger) Tracef(format string, args ...interface{}) {
	l.logWithContextf(l._tracef, format, args...)
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
