package cmd

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf/link"
	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
)

var detachCmd = &cobra.Command{
	Use:   "detach [interface]",
	Short: "Detach eBPF programs from a specified interface",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ifaceName := args[0]

		ouroborosConfig, err := ReadConfig()
		if err != nil {
			fmt.Println(err)
			return
		}

		program := ouroborosConfig.GetMainProgram()
		if program == nil {
			fmt.Println("main program is not defined in ouroboros.json")
			return
		}

		// Construct the link pin path
		linkPinPath := filepath.Join(ouroborosConfig.GetBpfBaseDir(), fmt.Sprintf("link_%s_%s", program.Name, ifaceName))

		// Try to use pinned link first (preferred method)
		if _, err := os.Stat(linkPinPath); err == nil {
			// Pinned link exists, use it
			l, err := link.LoadPinnedLink(linkPinPath, nil)
			if err != nil {
				fmt.Printf("Warning: failed to load pinned link from %s: %s\n", linkPinPath, err)
				fmt.Println("Falling back to netlink method...")

				// Fallback: Use netlink to detach XDP program
				iface, err := net.InterfaceByName(ifaceName)
				if err != nil {
					fmt.Printf("failed to get interface %s: %s\n", ifaceName, err)
					return
				}

				netlinkLink, err := netlink.LinkByIndex(iface.Index)
				if err != nil {
					fmt.Printf("failed to get netlink link by index %d: %s\n", iface.Index, err)
					return
				}

				// Detach XDP program by setting FD to -1
				if err := netlink.LinkSetXdpFd(netlinkLink, -1); err != nil {
					fmt.Printf("failed to detach program from interface %s: %s\n", ifaceName, err)
					return
				}
			} else {
				// Close the link to detach the program
				if err := l.Close(); err != nil {
					fmt.Printf("failed to detach program from interface %s: %s\n", ifaceName, err)
					return
				}

				// Remove the pinned link file
				if err := os.Remove(linkPinPath); err != nil {
					fmt.Printf("warning: failed to remove pinned link file at %s: %s\n", linkPinPath, err)
					return
				}
			}
		} else {
			fmt.Printf("No pinned link found at %s, using netlink fallback...\n", linkPinPath)
		}

		fmt.Printf("Successfully detached program from interface %s (via netlink)\n", ifaceName)
	},
}

func init() {
	RootCmd.AddCommand(detachCmd)
}
