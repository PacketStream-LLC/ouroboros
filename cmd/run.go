package cmd

import (
	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run [interface]",
	Short: "Build, load, attach, and show log at the same time",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		buildCmd.Run(cmd, []string{})
		loadCmd.Run(cmd, []string{})
		attachCmd.Run(cmd, args)
		logCmd.Run(cmd, []string{})
	},
}

func init() {
	RootCmd.AddCommand(runCmd)
}
