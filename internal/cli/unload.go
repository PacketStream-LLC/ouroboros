package cli

import (
	"github.com/PacketStream-LLC/ouroboros/internal/logger"

	"github.com/spf13/cobra"
)

var unloadCmd = &cobra.Command{
	Use:   "unload",
	Short: "Unload the compiled eBPF programs from the kernel and unpin maps",
	Run: func(cmd *cobra.Command, args []string) {
		// Get Ouroboros instance
		o := MustGetOuroboros(cmd)

		// Unload all programs using SDK
		errors := o.SDK().UnloadAllPrograms()

		// Report results
		successCount := len(o.SDK().ListPrograms()) - len(errors)
		for name, err := range errors {
			logger.Warn("Failed to unload program", "name", name, "error", err)
		}

		if len(errors) > 0 {
			logger.Info("Unload complete with errors",
				"success", successCount,
				"failed", len(errors))
		} else {
			logger.Info("Unload complete", "unloaded_count", successCount)
		}
	},
}
