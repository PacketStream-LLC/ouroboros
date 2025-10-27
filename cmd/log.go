package cmd

import (
	"os"

	"github.com/cilium/ebpf/rlimit"
	"github.com/spf13/cobra"
)

var logCmd = &cobra.Command{
	Use:   "log",
	Short: "Attach to kernel tracing for debugging ebpf_printk",
	Run: func(cmd *cobra.Command, args []string) {
		raw, _ := cmd.Flags().GetBool("raw")

		// Raw mode disables all logging
		if raw {
			SetRawMode(true)
		}

		if err := rlimit.RemoveMemlock(); err != nil {
			Fatal("Failed to remove memlock", "error", err)
		}

		Debug("Opening trace pipe", "path", "/sys/kernel/tracing/trace_pipe")

		file, err := os.Open("/sys/kernel/tracing/trace_pipe")
		if err != nil {
			Fatal("Failed to open trace_pipe", "error", err)
		}
		defer file.Close()

		Info("Reading from kernel trace pipe (Press Ctrl-C to stop)")

		buf := make([]byte, 1024)
		for {
			n, err := file.Read(buf)
			if err != nil {
				Fatal("Failed to read from trace_pipe", "error", err)
			}
			// Print trace output directly to stdout
			os.Stdout.Write(buf[:n])
		}
	},
}

