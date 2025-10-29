package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/PacketStream-LLC/ouroboros/internal/config"
	"github.com/PacketStream-LLC/ouroboros/internal/logger"
	"github.com/PacketStream-LLC/ouroboros/internal/utils"
	"github.com/PacketStream-LLC/ouroboros/pkg/constants"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/spf13/cobra"
)

var flowCmd = &cobra.Command{
	Use:   "flow [output_file]",
	Short: "Analyze the tail call flow of eBPF programs and generate a Mermaid flowchart",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Check for libbpf-dev (unless ignored)
		ignoreLibBPF, _ := cmd.Flags().GetBool("ignore-libbpf-detection")
		if !ignoreLibBPF {
			utils.DetectLibBPF()
		}

		// Resolve output file path relative to CWD before changing to project root
		outputFile := "flow.mermaid"
		if len(args) > 0 {
			outputFile = args[0]
		}
		outputFilePath, err := utils.ResolveCwdPath(outputFile)
		if err != nil {
			logger.Fatal("Failed to resolve output file path", "error", err)
		}

		// Execute in project root context
		if err := utils.WithProjectRoot(func() error {
			ouroborosConfig, err := config.ReadConfig()
			if err != nil {
				return fmt.Errorf("failed to read config: %w", err)
			}

			mainProg := ouroborosConfig.GetMainProgram()
			if mainProg == nil {
				return fmt.Errorf("main program not found in ouroboros.json. Please set 'is_main' to true for one of the programs")
			}

			logger.Debug("Building programs before flow analysis")
			buildCmd.Run(cmd, []string{})

			logger.Debug("Creating output file", "path", outputFilePath)
			return generateFlowChart(ouroborosConfig, mainProg, outputFilePath)
		}); err != nil {
			logger.Fatal("Failed to generate flow chart", "error", err)
		}
	},
}

func generateFlowChart(ouroborosConfig *config.OuroborosConfig, mainProg *config.Program, outputFilePath string) error {
	f, err := os.Create(outputFilePath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	logger.Info("Analyzing flow")
	var flowchart strings.Builder
	flowchart.WriteString("graph TD\n")
	analyzeProgram(nil, mainProg, ouroborosConfig, make(map[string]bool), &flowchart)
	fmt.Fprint(f, flowchart.String())
	logger.Info("Flowchart generated", "output", outputFilePath)
	return nil
}

func analyzeProgram(from *config.Program, prog *config.Program, cfg *config.OuroborosConfig, visited map[string]bool, flowchart *strings.Builder) {
	var nextFrom *config.Program
	if prog.Metadata != nil && prog.Metadata.HiddenOnFlow {
		nextFrom = from
	} else {
		nextFrom = prog
		if from != nil {
			flowchart.WriteString(fmt.Sprintf("    %s --> %s\n", from.Name, prog.Name))
		}
	}

	if visited[prog.Name] {
		return
	}
	visited[prog.Name] = true

	progSpec, err := ebpf.LoadCollectionSpec(filepath.Join(constants.TargetDir, fmt.Sprintf("%s.o", prog.Name)))
	if err != nil {
		logger.Fatal("Failed to load program object", "program", prog.Name, "error", err)
	}

	var nextProgs []*config.Program
	for _, p := range progSpec.Programs {
		insns := p.Instructions
		for i, ins := range insns {
			if ins.OpCode.JumpOp() == asm.Call && ins.Constant == int64(asm.FnTailCall) {
				if i > 0 && insns[i-1].OpCode.ALUOp() == asm.Mov && insns[i-1].Dst == asm.R3 {
					mapIndex := insns[i-1].Constant
					for j := range cfg.Programs {
						if cfg.Programs[j].ID == int(mapIndex) {
							nextProgs = append(nextProgs, &cfg.Programs[j])
						}
					}
				}
			}
		}
	}

	for _, nextProg := range nextProgs {
		analyzeProgram(nextFrom, nextProg, cfg, visited, flowchart)
	}
}
