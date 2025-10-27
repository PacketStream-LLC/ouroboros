package cmd

import (
	"fmt"
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
			fmt.Println("Nothing to clean: target directory does not exist.")
			return
		}

		// Remove the entire target directory
		fmt.Printf("Removing %s directory...\n", targetDir)
		if err := os.RemoveAll(targetDir); err != nil {
			fmt.Printf("Error: failed to remove %s: %v\n", targetDir, err)
			os.Exit(1)
		}

		// Also clean up any .ll or .o files in the root directory (just in case)
		cleanPatterns := []string{"*.ll", "*.o", "*.merged.o"}
		for _, pattern := range cleanPatterns {
			matches, err := filepath.Glob(pattern)
			if err != nil {
				continue
			}
			for _, file := range matches {
				fmt.Printf("Removing %s...\n", file)
				os.Remove(file)
			}
		}

		fmt.Println("Clean complete.")
	},
}

func init() {
	RootCmd.AddCommand(cleanCmd)
}
