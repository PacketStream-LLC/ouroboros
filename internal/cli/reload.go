package cli

import (
	"github.com/PacketStream-LLC/ouroboros/internal/logger"
	"github.com/spf13/cobra"
)

var reloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Unload and then load the eBPF programs and maps",
	Run: func(cmd *cobra.Command, args []string) {

		logger.Info("Unloading eBPF programs and maps")
		unloadCmd.Run(cmd, args)

		logger.Info("Loading eBPF programs and maps")
		loadCmd.Run(cmd, args)

		logger.Info("Reload complete")
	},
}
