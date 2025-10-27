package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use:   "ouroboros",
	Short: "A management tool for multiple eBPF programs",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Handle logging configuration
		logLevel, _ := cmd.Flags().GetString("log-level")
		verbose, _ := cmd.Flags().GetBool("verbose")

		// Verbose flag overrides log-level
		if verbose {
			SetVerbose(true)
		} else if logLevel != "" {
			SetLogLevelString(logLevel)
		}
	},
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	// Add global logging flags
	RootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output (debug level)")
	RootCmd.PersistentFlags().String("log-level", "", "Set log level (debug, info, warn, error)")

	// Register all subcommands
	RootCmd.AddCommand(
		addCmd,
		attachCmd,
		buildCmd,
		cleanCmd,
		createCmd,
		detachCmd,
		flowCmd,
		generateCmd,
		loadCmd,
		logCmd,
		mapCmd,
		mergeCmd,
		reloadCmd,
		runCmd,
		unloadCmd,
	)
}
