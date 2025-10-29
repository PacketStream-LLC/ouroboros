package cli

import (
	"github.com/PacketStream-LLC/ouroboros/internal/logger"

	"github.com/spf13/cobra"
)

var detachCmd = &cobra.Command{
	Use:   "detach [interface]",
	Short: "Detach eBPF programs from a specified interface",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ifaceName := args[0]

		// Get Ouroboros instance
		o := MustGetOuroboros(cmd)

		// Detach from interface using SDK
		if err := o.SDK().DetachByName(ifaceName); err != nil {
			logger.Fatal("Failed to detach program", "interface", ifaceName, "error", err)
		}

		logger.Info("Successfully detached program", "interface", ifaceName)
	},
}
