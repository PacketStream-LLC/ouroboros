package cli

import (
	"github.com/PacketStream-LLC/ouroboros/internal/core"
	"github.com/PacketStream-LLC/ouroboros/internal/logger"
	"github.com/spf13/cobra"
)

// contextKey is the key used to store the Ouroboros instance in cobra command context
type contextKey string

const ouroborosKey contextKey = "ouroboros"

// SetOuroboros stores the Ouroboros instance in the command context
func SetOuroboros(cmd *cobra.Command, o *core.Ouroboros) {
	cmd.SetContext(cmd.Context())
	cmd.Annotations = map[string]string{
		string(ouroborosKey): "", // We'll use a global variable instead for simplicity
	}
	globalOuroboros = o
}

// GetOuroboros retrieves the Ouroboros instance from the command context
// Returns nil if the instance hasn't been initialized
func GetOuroboros(cmd *cobra.Command) *core.Ouroboros {
	return globalOuroboros
}

// MustGetOuroboros retrieves the Ouroboros instance or creates one if it doesn't exist
func MustGetOuroboros(cmd *cobra.Command) *core.Ouroboros {
	if o := GetOuroboros(cmd); o != nil {
		return o
	}

	// Check if config path was specified via flag
	// Persistent flags are inherited by subcommands, so use Flags() which includes inherited flags
	configPath, _ := cmd.Flags().GetString("config")

	logger.Debug("MustGetOuroboros", "configPath", configPath)

	var o *core.Ouroboros
	var err error

	if configPath != "" {
		// Use specified config path
		o, err = core.NewFromPath(configPath)
	} else {
		// Try to create a new instance by loading config from CWD
		o, err = core.New()
	}

	if err != nil {
		// Return nil - commands should handle this appropriately
		// Some commands (like create) don't need existing config
		logger.Debug("MustGetOuroboros failed", "error", err)
		return nil
	}

	SetOuroboros(cmd, o)
	return o
}

// Global instance for simplicity (can be improved with proper context if needed)
var globalOuroboros *core.Ouroboros
