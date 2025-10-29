package cli

import (
	"os"
	"path/filepath"

	"github.com/PacketStream-LLC/ouroboros/pkg/constants"
	"github.com/PacketStream-LLC/ouroboros/internal/logger"

	"github.com/spf13/cobra"
)

var cleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Remove all build artifacts and temporary files",
	Long: `Removes the target directory containing compiled eBPF objects (.o files),
LLVM IR files (.ll files), and other build artifacts.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Check if target directory exists
		if _, err := os.Stat(constants.TargetDir); os.IsNotExist(err) {
			logger.Info("Nothing to clean: target directory does not exist")
			return
		}

		// Get Ouroboros instance (or create a temporary one if config doesn't exist)
		o := MustGetOuroboros(cmd)
		if o != nil {
			// Use OOP method if we have a valid instance
			if err := o.CleanBuildArtifacts(); err != nil {
				logger.Fatal("Failed to clean build artifacts", "error", err)
			}
		} else {
			// Fallback to direct cleaning if no config exists
			logger.Debug("Removing target directory", "path", constants.TargetDir)
			if err := os.RemoveAll(constants.TargetDir); err != nil {
				logger.Fatal("Failed to remove target directory", "path", constants.TargetDir, "error", err)
			}
			logger.Info("Removed target directory", "path", constants.TargetDir)
		}

		// Also clean up any .ll or .o files in the root directory (just in case)
		cleanPatterns := []string{"*.ll", "*.o", "*.merged.o"}
		for _, pattern := range cleanPatterns {
			matches, err := filepath.Glob(pattern)
			if err != nil {
				logger.Debug("Failed to glob pattern", "pattern", pattern, "error", err)
				continue
			}
			for _, file := range matches {
				logger.Debug("Removing file", "file", file)
				os.Remove(file)
			}
		}

		logger.Info("Clean complete")
	},
}
