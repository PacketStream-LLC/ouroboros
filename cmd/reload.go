package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var reloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Unload and then load the eBPF programs and maps",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Unloading eBPF programs and maps...")
		unloadCmd.Run(cmd, args)

		fmt.Println("Loading eBPF programs and maps...")
		loadCmd.Run(cmd, args)

		fmt.Println("Reload complete.")
	},
}

func init() {
	RootCmd.AddCommand(reloadCmd)
}
