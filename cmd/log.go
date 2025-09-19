package cmd

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf/rlimit"
	"github.com/spf13/cobra"
)

var logCmd = &cobra.Command{
	Use:   "log",
	Short: "Attach to kernel tracing for debugging ebpf_printk",
	Run: func(cmd *cobra.Command, args []string) {
		if err := rlimit.RemoveMemlock(); err != nil {
			fmt.Printf("failed to remove memlock: %s\n", err)
			return
		}

		file, err := os.Open("/sys/kernel/tracing/trace_pipe")
		if err != nil {
			fmt.Printf("failed to open trace_pipe: %s\n", err)
			return
		}
		defer file.Close()

		buf := make([]byte, 1024)
		for {
			n, err := file.Read(buf)
			if err != nil {
				fmt.Printf("failed to read from trace_pipe: %s\n", err)
				return
			}
			fmt.Print(string(buf[:n]))
		}
	},
}

func init() {
	RootCmd.AddCommand(logCmd)
}
