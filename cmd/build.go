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
			Fatal("libbpf-dev is not installed. Please install it first")
		}

		ouroborosConfig, err := ReadConfig()
		if err != nil {
			Fatal("Failed to read config", "error", err)
		}

		Debug("Starting build",
			"total_programs", len(ouroborosConfig.Programs),
			"compile_args", ouroborosConfig.CompileArgs)

		for i, prog := range ouroborosConfig.Programs {
			progName := prog.Name
			progDir := filepath.Join(srcDir, progName)
			mainC := filepath.Join(progDir, entryPointFile)
			outputO := filepath.Join(targetDir, fmt.Sprintf("%s.o", progName))

			Debug("Building program",
				"index", i+1,
				"total", len(ouroborosConfig.Programs),
				"name", progName,
				"source", mainC,
				"output", outputO)

			// check if filepath exists
			if _, err := os.Stat(targetDir); os.IsNotExist(err) {
				Debug("Creating target directory", "path", targetDir)
				err = os.MkdirAll(targetDir, 0755)
				if err != nil {
					Fatal("Failed to create target directory", "error", err, "path", targetDir)
				}
			}

			args := []string{"-O2", "-g", "-target", "bpf", "-c", mainC, "-o", outputO, "-Isrc/"}
			args = append(args, ouroborosConfig.CompileArgs...)

			Debug("Running clang", "args", args)

			clangCmd := exec.Command("clang", args...)
			clangCmd.Stdout = os.Stdout
			clangCmd.Stderr = os.Stderr
			if err := clangCmd.Run(); err != nil {
				Fatal("Compilation failed", "error", err, "program", progName)
			}

			Info("Compiled program", "name", progName, "output", outputO)
		}

		Info("Build complete")
	},
}

