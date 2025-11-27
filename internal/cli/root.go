package cli

import (
	"fmt"
	"os"

	"github.com/PacketStream-LLC/ouroboros/internal/logger"

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
			logger.SetVerbose(true)
		} else if logLevel != "" {
			logger.SetLogLevelString(logLevel)
		}

		// Initialize Ouroboros instance if config exists
		// Some commands (like create) will handle initialization themselves
		_ = MustGetOuroboros(cmd)
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

	// Add global behavior flags
	RootCmd.PersistentFlags().Bool("ignore-libbpf-detection", false, "Skip libbpf-dev detection check")

	// Add global config flag
	RootCmd.PersistentFlags().StringP("config", "c", "", "Path to ouroboros.json config file or project directory")

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
