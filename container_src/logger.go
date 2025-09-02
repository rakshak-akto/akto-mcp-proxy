package main

import (
	"fmt"
	"log"
	"os"
)

const LogPrefix = "[MCP-PROXY] "

// Logger wraps standard logger with a constant prefix
type Logger struct {
	logger *log.Logger
}

// NewLogger creates a new logger instance with the constant prefix
func NewLogger() *Logger {
	return &Logger{
		logger: log.New(os.Stdout, LogPrefix, log.LstdFlags|log.Lshortfile),
	}
}

// Printf logs a formatted message with the prefix
func (l *Logger) Printf(format string, v ...interface{}) {
	l.logger.Output(2, fmt.Sprintf(format, v...))
}

// Println logs a message with the prefix
func (l *Logger) Println(v ...interface{}) {
	l.logger.Output(2, fmt.Sprintln(v...))
}

// Print logs a message with the prefix
func (l *Logger) Print(v ...interface{}) {
	l.logger.Output(2, fmt.Sprint(v...))
}

// Fatalf logs a formatted message with the prefix and exits
func (l *Logger) Fatalf(format string, v ...interface{}) {
	l.logger.Output(2, fmt.Sprintf(format, v...))
	os.Exit(1)
}

// Fatal logs a message with the prefix and exits
func (l *Logger) Fatal(v ...interface{}) {
	l.logger.Output(2, fmt.Sprint(v...))
	os.Exit(1)
}

// Fatalln logs a message with the prefix and exits
func (l *Logger) Fatalln(v ...interface{}) {
	l.logger.Output(2, fmt.Sprintln(v...))
	os.Exit(1)
}

// Global logger instance
var Log = NewLogger()

// Convenience functions for direct usage

// Logf is a convenience function for formatted logging
func Logf(format string, v ...interface{}) {
	Log.Printf(format, v...)
}

// Logln is a convenience function for line logging
func Logln(v ...interface{}) {
	Log.Println(v...)
}

// LogFatal is a convenience function for fatal logging
func LogFatal(v ...interface{}) {
	Log.Fatal(v...)
}