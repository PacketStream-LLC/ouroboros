package cli

import (
	"strings"

	"github.com/PacketStream-LLC/ouroboros/internal/logger"
	sdk "github.com/PacketStream-LLC/ouroboros/pkg/ouroboros"

	"github.com/spf13/cobra"
)

var attachCmd = &cobra.Command{
	Use:   "attach [interface]",
	Short: "Attach eBPF programs to a specified interface",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ifaceName := args[0]

		// Get Ouroboros instance
		o := MustGetOuroboros(cmd)

		// Parse attach mode from flag
		modeStr, _ := cmd.Flags().GetString("mode")
		var mode sdk.AttachMode
		switch strings.ToLower(modeStr) {
		case "native":
			mode = sdk.AttachModeNative
		case "offload":
			mode = sdk.AttachModeOffload
		case "generic":
			mode = sdk.AttachModeGeneric
		default:
			logger.Fatal("Invalid attach mode", "mode", modeStr, "valid", "generic, native, offload")
		}

		// Attach main program using SDK
		opts := &sdk.AttachOptions{
			Mode: mode,
		}

		attached, err := o.SDK().AttachMainProgram(ifaceName, opts)
		if err != nil {
			logger.Fatal("Failed to attach program", "interface", ifaceName, "error", err)
		}

		logger.Info("Successfully attached program to interface",
			"interface", ifaceName,
			"program", attached.Program.Name,
			"mode", modeStr)
	},
}

func init() {
	attachCmd.Flags().StringP("mode", "m", "generic", "XDP attach mode: generic (default), native, or offload")
}
