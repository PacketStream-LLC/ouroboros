package cli

import (
	"os"
	"path/filepath"

	"github.com/PacketStream-LLC/ouroboros/pkg/constants"
	"github.com/PacketStream-LLC/ouroboros/internal/core"
	"github.com/PacketStream-LLC/ouroboros/internal/logger"

	"github.com/spf13/cobra"
)

var createCmd = &cobra.Command{
	Use:   "create [project_name]",
	Short: "Create a new ouroboros project",
	Long: `Create a new ouroboros project with the specified name.

The project name will be used as the default program map name (e.g., myproject_progs).
If no project name is provided, "ouroboros" will be used as default.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Get project name from args or use default
		projectName := "ouroboros"
		if len(args) > 0 {
			projectName = args[0]
		}

		// Get main program name from flag
		mainProgName, _ := cmd.Flags().GetString("main")

		// Construct program map name
		programMapName := projectName + "_progs"

		logger.Debug("Creating ouroboros project",
			"project", projectName,
			"main_program", mainProgName,
			"program_map", programMapName)

		// Initialize project with custom program map name
		o, err := core.InitializeProjectWithMap(mainProgName, programMapName)
		if err != nil {
			logger.Fatal("Failed to initialize project", "error", err)
		}

		// Store in context for subsequent commands
		SetOuroboros(cmd, o)

		// Create src/_global directory (legacy support)
		globalDir := filepath.Join(constants.SrcDir, constants.DefaultGlobalDirName)
		logger.Debug("Creating global directory", "path", globalDir)
		if err := os.MkdirAll(globalDir, 0755); err != nil {
			logger.Fatal("Failed to create global directory", "path", globalDir, "error", err)
		}

		// Generate programs header
		logger.Debug("Generating programs header")
		if err := GenerateProgramsHeader(o.Config()); err != nil {
			logger.Fatal("Failed to generate programs header", "error", err)
		}

		logger.Info("Ouroboros project created successfully",
			"project", projectName,
			"main_program", mainProgName,
			"program_map", programMapName)
	},
}

func init() {
	createCmd.Flags().StringP("main", "m", constants.DefaultMainProgramName, "Name of the main program")
}
