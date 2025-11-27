package cli

import (
	"os"
	"path/filepath"

	"github.com/PacketStream-LLC/ouroboros/internal/logger"
	"github.com/PacketStream-LLC/ouroboros/internal/utils"
	"github.com/PacketStream-LLC/ouroboros/pkg/constants"

	"github.com/spf13/cobra"
)

var cleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Remove all build artifacts and temporary files",
	Long: `Removes the target directory containing compiled eBPF objects (.o files),
LLVM IR files (.ll files), and other build artifacts.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Get Ouroboros instance (respects --config flag)
		o := MustGetOuroboros(cmd)
		if o == nil {
			// Fallback to CWD-based cleaning if no config exists
			if _, err := os.Stat(constants.TargetDir); os.IsNotExist(err) {
				logger.Info("Nothing to clean: target directory does not exist")
				return
			}
			logger.Debug("Removing target directory", "path", constants.TargetDir)
			if err := os.RemoveAll(constants.TargetDir); err != nil {
				logger.Fatal("Failed to remove target directory", "path", constants.TargetDir, "error", err)
			}
			logger.Info("Removed target directory", "path", constants.TargetDir)
			logger.Info("Clean complete")
			return
		}

		// Get project root from the config-aware instance
		projectRoot, err := o.SDK().GetProjectRoot()
		if err != nil {
			logger.Fatal("Failed to get project root", "error", err)
		}

		// Execute in project root context
		if err := utils.WithProjectRootPath(projectRoot, func() error {
			// Check if target directory exists
			if _, err := os.Stat(constants.TargetDir); os.IsNotExist(err) {
				logger.Info("Nothing to clean: target directory does not exist")
				return nil
			}

			// Use OOP method
			if err := o.CleanBuildArtifacts(); err != nil {
				return err
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

			return nil
		}); err != nil {
			logger.Fatal("Failed to clean build artifacts", "error", err)
		}

		logger.Info("Clean complete")
	},
}
