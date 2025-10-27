package cmd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"golang.org/x/term"
)

// Global logger instance
var logger *slog.Logger

// Log level variable
var logLevel = new(slog.LevelVar)

// Raw mode flag - when true, completely disables logging
var rawMode = false

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
)

// CompactHandler is a custom slog handler that formats messages cleanly
type CompactHandler struct {
	opts      slog.HandlerOptions
	w         io.Writer
	attrs     []slog.Attr
	group     string
	useColors bool
}

func NewCompactHandler(w io.Writer, opts *slog.HandlerOptions) *CompactHandler {
	if opts == nil {
		opts = &slog.HandlerOptions{}
	}

	// Detect if output supports colors
	useColors := shouldUseColors(w)

	return &CompactHandler{
		opts:      *opts,
		w:         w,
		useColors: useColors,
	}
}

// shouldUseColors determines if colors should be enabled based on terminal detection and environment
func shouldUseColors(w io.Writer) bool {
	// Check NO_COLOR environment variable (standard)
	if os.Getenv("NO_COLOR") != "" {
		return false
	}

	// Check FORCE_COLOR environment variable
	if os.Getenv("FORCE_COLOR") != "" {
		return true
	}

	// Check if output is a terminal
	if f, ok := w.(*os.File); ok {
		return term.IsTerminal(int(f.Fd()))
	}

	return false
}

func (h *CompactHandler) Enabled(ctx context.Context, level slog.Level) bool {
	minLevel := slog.LevelInfo
	if h.opts.Level != nil {
		minLevel = h.opts.Level.Level()
	}
	return level >= minLevel
}

func (h *CompactHandler) Handle(ctx context.Context, r slog.Record) error {
	var prefix, color, reset string

	if h.useColors {
		reset = colorReset
		switch r.Level {
		case slog.LevelDebug:
			color = colorGray
			prefix = "DEBUG: "
		case slog.LevelInfo:
			color = ""
			prefix = ""
		case slog.LevelWarn:
			color = colorYellow
			prefix = "WARNING: "
		case slog.LevelError:
			color = colorRed
			prefix = "ERROR: "
		}
	} else {
		switch r.Level {
		case slog.LevelDebug:
			prefix = "DEBUG: "
		case slog.LevelInfo:
			prefix = ""
		case slog.LevelWarn:
			prefix = "WARNING: "
		case slog.LevelError:
			prefix = "ERROR: "
		}
	}

	// Build the message
	msg := fmt.Sprintf("%s%s%s", color, prefix, r.Message)

	// Add attributes if any
	var attrs []string
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, fmt.Sprintf("%s=%v", a.Key, a.Value))
		return true
	})

	if len(attrs) > 0 {
		msg += " ("
		for i, attr := range attrs {
			if i > 0 {
				msg += ", "
			}
			msg += attr
		}
		msg += ")"
	}

	// Add reset code at the end if using colors
	if h.useColors && reset != "" {
		msg += reset
	}

	fmt.Fprintln(h.w, msg)
	return nil
}

func (h *CompactHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &CompactHandler{
		opts:      h.opts,
		w:         h.w,
		attrs:     append(h.attrs, attrs...),
		group:     h.group,
		useColors: h.useColors,
	}
}

func (h *CompactHandler) WithGroup(name string) slog.Handler {
	return &CompactHandler{
		opts:      h.opts,
		w:         h.w,
		attrs:     h.attrs,
		group:     name,
		useColors: h.useColors,
	}
}

func init() {
	// Initialize with INFO level by default
	logLevel.Set(slog.LevelInfo)

	// Create a compact handler that writes to stderr
	handler := NewCompactHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	})

	logger = slog.New(handler)
	slog.SetDefault(logger)
}

// SetVerbose sets the log level based on verbose flag
func SetVerbose(verbose bool) {
	if verbose {
		logLevel.Set(slog.LevelDebug)
	} else {
		logLevel.Set(slog.LevelInfo)
	}
}

// SetRawMode enables or disables raw mode (bypasses all logging)
func SetRawMode(raw bool) {
	rawMode = raw
	if raw {
		// Set level extremely high to effectively disable all logging
		logLevel.Set(slog.Level(1000))
	}
}

// IsRawMode returns whether raw mode is enabled
func IsRawMode() bool {
	return rawMode
}

// SetLogLevel sets the log level explicitly
func SetLogLevel(level slog.Level) {
	logLevel.Set(level)
}

// SetLogLevelString sets the log level from a string (debug, info, warn, error)
func SetLogLevelString(level string) {
	switch level {
	case "debug":
		logLevel.Set(slog.LevelDebug)
	case "info":
		logLevel.Set(slog.LevelInfo)
	case "warn":
		logLevel.Set(slog.LevelWarn)
	case "error":
		logLevel.Set(slog.LevelError)
	default:
		logLevel.Set(slog.LevelInfo)
	}
}

// GetLogger returns the global logger instance
func GetLogger() *slog.Logger {
	return logger
}

// Convenience functions for common logging patterns

// Info logs an informational message
func Info(msg string, args ...any) {
	logger.Info(msg, args...)
}

// Debug logs a debug message (only shown when verbose is enabled)
func Debug(msg string, args ...any) {
	logger.Debug(msg, args...)
}

// Warn logs a warning message
func Warn(msg string, args ...any) {
	logger.Warn(msg, args...)
}

// Error logs an error message
func Error(msg string, args ...any) {
	logger.Error(msg, args...)
}

// Fatal logs an error message and exits with status 1
func Fatal(msg string, args ...any) {
	logger.Error(msg, args...)
	os.Exit(1)
}
