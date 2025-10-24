package cmd

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
)

var detachCmd = &cobra.Command{
	Use:   "detach [interface]",
	Short: "Detach eBPF programs from a specified interface",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ifaceName := args[0]

		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			fmt.Printf("failed to get interface %s: %s\n", ifaceName, err)
			return
		}

		link, err := netlink.LinkByIndex(iface.Index)
		if err != nil {
			fmt.Printf("failed to get link by index %d: %s\n", iface.Index, err)
			return
		}

		if err := netlink.LinkSetXdpFd(link, -1); err != nil {
			fmt.Printf("failed to detach program from interface %s: %s\n", ifaceName, err)
			return
		}

		// Clean up pinned link file if it exists
		ouroborosConfig, err := ReadConfig()
		if err == nil {
			program := ouroborosConfig.GetMainProgram()
			if program != nil {
				linkPinPath := filepath.Join(ouroborosConfig.GetBpfBaseDir(), fmt.Sprintf("link_%s_%s", program.Name, ifaceName))
				if _, err := os.Stat(linkPinPath); err == nil {
					if err := os.Remove(linkPinPath); err != nil {
						fmt.Printf("warning: failed to remove pinned link at %s: %s\n", linkPinPath, err)
					}
				}
			}
		}

		fmt.Printf("Successfully detached program from interface %s\n", ifaceName)
	},
}

func init() {
	RootCmd.AddCommand(detachCmd)
}
