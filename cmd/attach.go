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

		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			fmt.Printf("failed to get interface %s: %s\n", ifaceName, err)
			return
		}

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

		progPinPath := filepath.Join(ouroborosConfig.GetBpfBaseDir(), ouroborosConfig.ProgramPrefix+program.Name)
		prog, err := ebpf.LoadPinnedProgram(progPinPath, nil)
		if err != nil {
			fmt.Printf("failed to load pinned program %s: %s\n", progPinPath, err)
			return
		}
		defer prog.Close()

		// Attach the program to the interface
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: iface.Index,
		})
		if err != nil {
			fmt.Printf("failed to attach program to interface %s: %s\n", ifaceName, err)
			return
		}

		// Pin the link to persist the attachment
		linkPinPath := filepath.Join(ouroborosConfig.GetBpfBaseDir(), fmt.Sprintf("link_%s_%s", program.Name, ifaceName))

		// Remove existing link pin if it exists
		os.Remove(linkPinPath)

		if err := l.Pin(linkPinPath); err != nil {
			l.Close()
			fmt.Printf("failed to pin link to %s: %s\n", linkPinPath, err)
			return
		}

		fmt.Printf("Successfully attached program to interface %s\n", ifaceName)
		fmt.Printf("Link pinned at: %s\n", linkPinPath)
	},
}

func init() {
	RootCmd.AddCommand(attachCmd)
}
