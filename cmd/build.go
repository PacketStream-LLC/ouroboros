package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

var buildCmd = &cobra.Command{
	Use:   "build",
	Short: "Compile all eBPF programs in the project",
	Run: func(cmd *cobra.Command, args []string) {
		if _, err := os.Stat("/usr/include/bpf/bpf.h"); os.IsNotExist(err) {
			fmt.Println("libbpf-dev is not installed. Please install it first.")
			os.Exit(1)
		}

		ouroborosConfig, err := ReadConfig()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		for _, prog := range ouroborosConfig.Programs {
			progName := prog.Name
			progDir := filepath.Join(srcDir, progName)
			mainC := filepath.Join(progDir, entryPointFile)
			outputO := filepath.Join(targetDir, fmt.Sprintf("%s.o", progName))

			// check if filepath exists
			if _, err := os.Stat(targetDir); os.IsNotExist(err) {
				err = os.MkdirAll(targetDir, 0755)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
			}

			args := []string{"-O2", "-g", "-target", "bpf", "-c", mainC, "-o", outputO, "-Isrc/"}
			args = append(args, ouroborosConfig.CompileArgs...)

			clangCmd := exec.Command("clang", args...)
			clangCmd.Stdout = os.Stdout
			clangCmd.Stderr = os.Stderr
			if err := clangCmd.Run(); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}

		fmt.Println("Build complete.")
	},
}

func init() {
	RootCmd.AddCommand(buildCmd)
}
