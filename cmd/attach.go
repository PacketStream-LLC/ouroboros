package cmd

import (
	"fmt"
	"net"
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

		pinPath := filepath.Join(bpfBaseDir, ouroborosConfig.ProgramPrefix+program.Name)
		prog, err := ebpf.LoadPinnedProgram(pinPath, nil)
		if err != nil {
			fmt.Printf("failed to load pinned program %s: %s\n", pinPath, err)
			return
		}

		// Attach the program.
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: iface.Index,
		})
		if err != nil {
			fmt.Printf("failed to attach program to interface %s: %s\n", ifaceName, err)
			return
		}
		defer l.Close()

		fmt.Printf("Successfully attached program to interface %s\n", ifaceName)
	},
}

func init() {
	RootCmd.AddCommand(attachCmd)
}
