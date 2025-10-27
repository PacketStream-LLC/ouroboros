package cmd

import (
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
			Fatal("Failed to read config", "error", err)
		}

		Debug("Unloading eBPF programs",
			"bpf_base_dir", config.GetBpfBaseDir(),
			"program_prefix", config.ProgramPrefix,
			"total_programs", len(config.Programs))

		// Unpin programs
		successCount := 0
		failCount := 0
		for i, prog := range config.Programs {
			progPath := filepath.Join(config.GetBpfBaseDir(), config.ProgramPrefix+prog.Name)

			Debug("Unpinning program",
				"index", i+1,
				"total", len(config.Programs),
				"name", prog.Name,
				"path", progPath)

			if err := os.Remove(progPath); err != nil {
				Warn("Failed to unpin program",
					"program", prog.Name,
					"error", err)
				failCount++
				// Don't exit, try to unpin other programs
			} else {
				Info("Unpinned program", "name", prog.Name)
				successCount++
			}
		}

		Debug("Program unload summary",
			"success", successCount,
			"failed", failCount)

		// Unpin program array map
		progMapPath := filepath.Join(config.GetBpfBaseDir(), config.GetProgramMap())

		Debug("Unpinning program array map",
			"name", config.GetProgramMap(),
			"path", progMapPath)

		if err := os.Remove(progMapPath); err != nil {
			Fatal("Failed to unpin program array map",
				"map", config.GetProgramMap(),
				"error", err)
		}

		Info("Unpinned program array map", "name", config.GetProgramMap())

		Info("Unload complete")
	},
}

