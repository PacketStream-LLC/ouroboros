package cmd

import (
	"github.com/spf13/cobra"
)

var reloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Unload and then load the eBPF programs and maps",
	Run: func(cmd *cobra.Command, args []string) {

		Info("Unloading eBPF programs and maps")
		unloadCmd.Run(cmd, args)

		Info("Loading eBPF programs and maps")
		loadCmd.Run(cmd, args)

		Info("Reload complete")
	},
}

