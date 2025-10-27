package cmd

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/spf13/cobra"
)

var attachCmd = &cobra.Command{
	Use:   "attach [interface]",
	Short: "Attach eBPF programs to a specified interface",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {

		ifaceName := args[0]

		Debug("Looking up interface", "name", ifaceName)

		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			Fatal("Failed to get interface", "interface", ifaceName, "error", err)
		}

		Debug("Found interface",
			"name", ifaceName,
			"index", iface.Index,
			"mtu", iface.MTU,
			"mac", iface.HardwareAddr)

		ouroborosConfig, err := ReadConfig()
		if err != nil {
			Fatal("Failed to read config", "error", err)
		}

		program := ouroborosConfig.GetMainProgram()
		if program == nil {
			Fatal("Main program is not defined in ouroboros.json")
		}

		Debug("Using main program", "name", program.Name)

		progPinPath := filepath.Join(ouroborosConfig.GetBpfBaseDir(), ouroborosConfig.ProgramPrefix+program.Name)

		Debug("Loading pinned program", "path", progPinPath)

		prog, err := ebpf.LoadPinnedProgram(progPinPath, nil)
		if err != nil {
			Fatal("Failed to load pinned program", "path", progPinPath, "error", err)
		}
		defer prog.Close()

		// Attach the program to the interface
		Debug("Attaching XDP program to interface", "interface", ifaceName)

		l, err := link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: iface.Index,
		})
		if err != nil {
			Fatal("Failed to attach program to interface", "interface", ifaceName, "error", err)
		}

		// Pin the link to persist the attachment
		linkPinPath := filepath.Join(ouroborosConfig.GetBpfBaseDir(), fmt.Sprintf("link_%s_%s", program.Name, ifaceName))

		// Remove existing link pin if it exists
		if _, err := os.Stat(linkPinPath); err == nil {
			Debug("Removing existing link pin", "path", linkPinPath)
			os.Remove(linkPinPath)
		}

		Debug("Pinning link", "path", linkPinPath)

		if err := l.Pin(linkPinPath); err != nil {
			l.Close()
			Fatal("Failed to pin link", "path", linkPinPath, "error", err)
		}

		Info("Successfully attached program to interface",
			"interface", ifaceName,
			"program", program.Name,
			"link_path", linkPinPath)
	},
}

