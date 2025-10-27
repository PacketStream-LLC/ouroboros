package cmd

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var cleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Remove all build artifacts and temporary files",
	Long: `Removes the target directory containing compiled eBPF objects (.o files),
LLVM IR files (.ll files), and other build artifacts.`,
	Run: func(cmd *cobra.Command, args []string) {

		// Check if target directory exists
		if _, err := os.Stat(targetDir); os.IsNotExist(err) {
			Info("Nothing to clean: target directory does not exist")
			return
		}

		Debug("Removing target directory", "path", targetDir)

		// Remove the entire target directory
		if err := os.RemoveAll(targetDir); err != nil {
			Fatal("Failed to remove target directory", "path", targetDir, "error", err)
		}

		Info("Removed target directory", "path", targetDir)

		// Also clean up any .ll or .o files in the root directory (just in case)
		cleanPatterns := []string{"*.ll", "*.o", "*.merged.o"}
		for _, pattern := range cleanPatterns {
			matches, err := filepath.Glob(pattern)
			if err != nil {
				Debug("Failed to glob pattern", "pattern", pattern, "error", err)
				continue
			}
			for _, file := range matches {
				Debug("Removing file", "file", file)
				os.Remove(file)
			}
		}

		Info("Clean complete")
	},
}

