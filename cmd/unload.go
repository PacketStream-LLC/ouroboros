package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var unloadCmd = &cobra.Command{
	Use:   "unload",
	Short: "Unload the compiled eBPF programs from the kernel and unpin maps",
	Run: func(cmd *cobra.Command, args []string) {
		config, err := ReadConfig()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Unpin programs
		for _, prog := range config.Programs {
			progPath := filepath.Join(config.GetBpfBaseDir(), config.ProgramPrefix+prog.Name)
			if err := os.Remove(progPath); err != nil {
				fmt.Printf("failed to unpin program %s: %v\n", prog.Name, err)
				// Don't exit, try to unpin other programs
			}
			fmt.Printf("Unpinned program %s\n", prog.Name)
		}

		// Unpin program array map
		progMapPath := filepath.Join(config.GetBpfBaseDir(), config.GetProgramMap())
		if err := os.Remove(progMapPath); err != nil {
			fmt.Printf("failed to unpin program array map %s: %v\n", config.GetProgramMap(), err)
			os.Exit(1)
		}
		fmt.Printf("Unpinned program array map %s\n", config.GetProgramMap())

		fmt.Println("Unload complete.")
	},
}

func init() {
	RootCmd.AddCommand(unloadCmd)
}
