package cli

import (
	"os"
	"path/filepath"

	"github.com/PacketStream-LLC/ouroboros/internal/config"
	"github.com/PacketStream-LLC/ouroboros/internal/logger"
	"github.com/PacketStream-LLC/ouroboros/internal/utils"
	"github.com/PacketStream-LLC/ouroboros/pkg/constants"
	sdk "github.com/PacketStream-LLC/ouroboros/pkg/ouroboros"

	"github.com/spf13/cobra"
)

var buildCmd = &cobra.Command{
	Use:   "build",
	Short: "Compile all eBPF programs in the project",
	Run: func(cmd *cobra.Command, args []string) {
		// Check for libbpf-dev (unless ignored)
		ignoreLibBPF, _ := cmd.Flags().GetBool("ignore-libbpf-detection")
		if !ignoreLibBPF {
			utils.DetectLibBPF()
		}

		// Get Ouroboros instance first (respects --config flag)
		o := MustGetOuroboros(cmd)
		if o == nil {
			logger.Fatal("Failed to initialize ouroboros - config not found")
		}

		// Get project root from the config-aware instance
		projectRoot, err := o.SDK().GetProjectRoot()
		if err != nil {
			logger.Fatal("Failed to get project root", "error", err)
		}

		// Execute in project root context
		if err := utils.WithProjectRootPath(projectRoot, func() error {
			// Check if _ouroboros directory exists, generate if not
			ouroborosDir := filepath.Join(constants.SrcDir, "_ouroboros")
			if _, err := os.Stat(ouroborosDir); os.IsNotExist(err) {
				logger.Info("_ouroboros directory not found, running generate first")

				ouroborosConfig, err := config.ReadConfig()
				if err != nil {
					logger.Fatal("Failed to read config", "error", err)
				}

				if err := GenerateProgramsHeader(ouroborosConfig); err != nil {
					logger.Fatal("Failed to generate programs header", "error", err)
				}

				logger.Info("Generated _ouroboros files successfully")
			}

			// CLI shows build output by default (SDK is silent by default)
			opts := &sdk.BuildOptions{
				Stdout: os.Stdout,
				Stderr: os.Stderr,
			}

			results := o.SDK().BuildAll(opts)

			// Report results
			var failed []string
			for name, err := range results {
				if err != nil {
					logger.Error("Build failed", "program", name, "error", err)
					failed = append(failed, name)
				} else {
					logger.Info("Compiled program", "name", name)
				}
			}

			if len(failed) > 0 {
				logger.Fatal("Build failed for some programs", "failed", failed)
			}

			logger.Info("Build complete")
			return nil
		}); err != nil {
			logger.Fatal("Failed to execute build", "error", err)
		}
	},
}
