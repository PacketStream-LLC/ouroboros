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
			Fatal("Failed to read config", "error", err)
		}

		program := ouroborosConfig.GetMainProgram()
		if program == nil {
			Fatal("Main program is not defined in ouroboros.json")
		}

		Debug("Using main program", "name", program.Name)

		// Construct the link pin path
		linkPinPath := filepath.Join(ouroborosConfig.GetBpfBaseDir(), fmt.Sprintf("link_%s_%s", program.Name, ifaceName))

		Debug("Looking for pinned link", "path", linkPinPath)

		// Try to use pinned link first (preferred method)
		if _, err := os.Stat(linkPinPath); err == nil {
			// Pinned link exists, use it
			Debug("Found pinned link, attempting to load")

			l, err := link.LoadPinnedLink(linkPinPath, nil)
			if err != nil {
				Warn("Failed to load pinned link, falling back to netlink method",
					"path", linkPinPath,
					"error", err)

				// Fallback: Use netlink to detach XDP program
				iface, err := net.InterfaceByName(ifaceName)
				if err != nil {
					Fatal("Failed to get interface", "interface", ifaceName, "error", err)
				}

				Debug("Using netlink fallback", "interface_index", iface.Index)

				netlinkLink, err := netlink.LinkByIndex(iface.Index)
				if err != nil {
					Fatal("Failed to get netlink link", "index", iface.Index, "error", err)
				}

				// Detach XDP program by setting FD to -1
				Debug("Detaching XDP program via netlink")

				if err := netlink.LinkSetXdpFd(netlinkLink, -1); err != nil {
					Fatal("Failed to detach program from interface", "interface", ifaceName, "error", err)
				}

				Info("Successfully detached program (via netlink)", "interface", ifaceName)
			} else {
				// Close the link to detach the program
				Debug("Closing link to detach program")

				if err := l.Close(); err != nil {
					Fatal("Failed to detach program from interface", "interface", ifaceName, "error", err)
				}

				// Remove the pinned link file
				Debug("Removing pinned link file", "path", linkPinPath)

				if err := os.Remove(linkPinPath); err != nil {
					Warn("Failed to remove pinned link file", "path", linkPinPath, "error", err)
				}

				Info("Successfully detached program (via pinned link)",
					"interface", ifaceName,
					"program", program.Name)
			}
		} else {
			Debug("No pinned link found, using netlink fallback")

			// Fallback: Use netlink to detach XDP program
			iface, err := net.InterfaceByName(ifaceName)
			if err != nil {
				Fatal("Failed to get interface", "interface", ifaceName, "error", err)
			}

			netlinkLink, err := netlink.LinkByIndex(iface.Index)
			if err != nil {
				Fatal("Failed to get netlink link", "index", iface.Index, "error", err)
			}

			// Detach XDP program by setting FD to -1
			Debug("Detaching XDP program via netlink")

			if err := netlink.LinkSetXdpFd(netlinkLink, -1); err != nil {
				Fatal("Failed to detach program from interface", "interface", ifaceName, "error", err)
			}

			Info("Successfully detached program (via netlink)", "interface", ifaceName)
		}
	},
}

