package cli

import (
	_ "embed"

	"github.com/PacketStream-LLC/ouroboros/internal/logger"

	"github.com/spf13/cobra"
)

//go:embed templates/main.c.tmpl
var mainCTemplate string

var addCmd = &cobra.Command{
	Use:   "add [prog_name]",
	Short: "Add a new eBPF program to the project",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		progName := args[0]

		// Get Ouroboros instance
		o := MustGetOuroboros(cmd)
		if o == nil {
			logger.Fatal("Failed to load configuration. Is this an ouroboros project?")
		}

		// Add the program using OOP method
		if err := o.AddNewProgram(progName, mainCTemplate); err != nil {
			logger.Fatal("Failed to add program", "error", err)
		}

		// Run post-program-add hooks
		logger.Debug("Running post-program-add hooks")
		if err := RunPostProgramAdd(o.Config()); err != nil {
			logger.Fatal("Failed to run post-program-add hooks", "error", err)
		}
	},
}
