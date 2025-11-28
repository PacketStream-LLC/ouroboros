package ouroboros

import (
	"log/slog"

	"github.com/PacketStream-LLC/ouroboros/internal/logger"
)

// LogLevel represents a logging level
type LogLevel int

const (
	LogLevelDebug LogLevel = LogLevel(slog.LevelDebug)
	LogLevelInfo  LogLevel = LogLevel(slog.LevelInfo)
	LogLevelWarn  LogLevel = LogLevel(slog.LevelWarn)
	LogLevelError LogLevel = LogLevel(slog.LevelError)
)

// SetLogLevel sets the global log level for the Ouroboros SDK.
// This affects all logging output from the SDK.
func SetLogLevel(level LogLevel) {
	logger.SetLogLevel(slog.Level(level))
}

// SetLogLevelString sets the global log level from a string.
// Valid values are: "debug", "info", "warn", "error".
// Invalid values default to "info".
func SetLogLevelString(level string) {
	logger.SetLogLevelString(level)
}

// SetVerbose enables or disables verbose (debug) logging.
// This is a convenience function equivalent to SetLogLevel(LogLevelDebug).
func SetVerbose(verbose bool) {
	logger.SetVerbose(verbose)
}

// SetSilent disables all logging output from the SDK.
// Useful when using the SDK as a library where you want to handle
// logging yourself or suppress all output.
func SetSilent(silent bool) {
	if silent {
		logger.SetLogLevel(slog.Level(1000)) // Effectively disable all logging
	} else {
		logger.SetLogLevel(slog.LevelInfo)
	}
}
