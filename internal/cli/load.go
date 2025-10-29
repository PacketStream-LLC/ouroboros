package cli

import (
	"github.com/PacketStream-LLC/ouroboros/internal/logger"

	"github.com/spf13/cobra"
)

var loadCmd = &cobra.Command{
	Use:   "load",
	Short: "Load the compiled eBPF programs into the kernel",
	Run: func(cmd *cobra.Command, args []string) {
		// Get Ouroboros instance
		o := MustGetOuroboros(cmd)

		// Load all programs using SDK
		loaded, errors := o.SDK().LoadAllPrograms(nil)

		// Report results
		for name := range loaded {
			err := errors[name]
			if err != nil {
				logger.Error("Failed to load program", "name", name, "error", err)
			} else {
				logger.Info("Loaded program", "name", name)
			}
		}

		if len(errors) > 0 {
			logger.Fatal("Failed to load some programs", "failed_count", len(errors))
		}

		logger.Info("Load complete", "loaded_count", len(loaded))
	},
}
