package cli

import (
	"github.com/PacketStream-LLC/ouroboros/internal/logger"
	"github.com/PacketStream-LLC/ouroboros/internal/utils"
	sdk "github.com/PacketStream-LLC/ouroboros/pkg/ouroboros"

	"github.com/spf13/cobra"
)

var loadCmd = &cobra.Command{
	Use:   "load",
	Short: "Load the compiled eBPF programs into the kernel",
	Run: func(cmd *cobra.Command, args []string) {
		// Get Ouroboros instance
		o := MustGetOuroboros(cmd)

		// Check if verbose flag is set
		verbose := utils.IsVerbose(cmd)

		// Check if recreate-progmaps flag is set
		recreateProgmaps, _ := cmd.Flags().GetBool("recreate-progmaps")

		// Load all programs using SDK
		opts := &sdk.LoadOptions{
			RecreateProgramMap: recreateProgmaps,
		}
		loaded, errors := o.SDK().LoadAllPrograms(opts)

		// Report results
		for name := range loaded {
			err := errors[name]
			if err != nil {
				logger.Error("Failed to load program", "name", name, "error", err)
			} else {
				logger.Info("Loaded program", "name", name)
			}
		}

		// If there are errors and verbose is enabled, print detailed error information
		if len(errors) > 0 {
			if verbose {
				logger.Error("Detailed error information:")
				for name, err := range errors {
					logger.Error("  Program failed", "name", name, "error", err)
				}
			}
			logger.Fatal("Failed to load some programs", "failed_count", len(errors))
		}

		logger.Info("Load complete", "loaded_count", len(loaded))
	},
}

func init() {
	loadCmd.Flags().Bool("recreate-progmaps", false, "Automatically recreate program maps if incompatible")
}
