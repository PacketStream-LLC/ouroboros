package cmd

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new ouroboros project",
	Run: func(cmd *cobra.Command, args []string) {

		Debug("Creating ouroboros project")

		Debug("Creating source directory", "path", srcDir)
		if err := os.Mkdir(srcDir, 0755); err != nil {
			Fatal("Failed to create source directory", "path", srcDir, "error", err)
		}

		Debug("Creating target directory", "path", targetDir)
		if err := os.Mkdir(targetDir, 0755); err != nil {
			Fatal("Failed to create target directory", "path", targetDir, "error", err)
		}

		// Create src/_global directory
		globalDir := filepath.Join(srcDir, "_global")
		Debug("Creating global directory", "path", globalDir)
		if err := os.MkdirAll(globalDir, 0755); err != nil {
			Fatal("Failed to create global directory", "path", globalDir, "error", err)
		}

		// Create src/_ouroboros directory
		Debug("Creating ouroboros global directory", "path", ouroborosGlobalDir)
		if err := os.MkdirAll(ouroborosGlobalDir, 0755); err != nil {
			Fatal("Failed to create ouroboros global directory", "path", ouroborosGlobalDir, "error", err)
		}

		Debug("Creating default configuration")
		ouroborosConfig := &OuroborosConfig{
			Programs: []Program{
				{Name: "main", ID: 1, IsMain: true},
			},
			CompileArgs: []string{"-Wall"},
		}

		Debug("Writing configuration file")
		if err := WriteConfig(ouroborosConfig); err != nil {
			Fatal("Failed to write config", "error", err)
		}

		Debug("Generating programs header")
		if err := GenerateProgramsHeader(ouroborosConfig); err != nil {
			Fatal("Failed to generate programs header", "error", err)
		}

		Info("Ouroboros project created successfully")
	},
}

