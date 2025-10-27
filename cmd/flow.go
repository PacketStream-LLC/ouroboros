package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/spf13/cobra"
)

var flowCmd = &cobra.Command{
	Use:   "flow [output_file]",
	Short: "Analyze the tail call flow of eBPF programs and generate a Mermaid flowchart",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {

		if _, err := os.Stat("/usr/include/bpf/bpf.h"); os.IsNotExist(err) {
			Fatal("libbpf-dev is not installed. Please install it first")
		}

		ouroborosConfig, err := ReadConfig()
		if err != nil {
			Fatal("Failed to read config", "error", err)
		}

		mainProg := ouroborosConfig.GetMainProgram()
		if mainProg == nil {
			Fatal("Main program not found in ouroboros.json. Please set 'is_main' to true for one of the programs")
		}

		Debug("Building programs before flow analysis")
		buildCmd.Run(cmd, []string{})

		outputFile := "flow.mermaid"
		if len(args) > 0 {
			outputFile = args[0]
		}

		Debug("Creating output file", "path", outputFile)

		f, err := os.Create(outputFile)
		if err != nil {
			Fatal("Failed to create output file", "path", outputFile, "error", err)
		}
		defer f.Close()

		Info("Analyzing flow")
		var flowchart strings.Builder
		flowchart.WriteString("graph TD\n")
		analyzeProgram(nil, mainProg, ouroborosConfig, make(map[string]bool), &flowchart)
		fmt.Fprint(f, flowchart.String())
		Info("Flowchart generated", "output", outputFile)
	},
}

func analyzeProgram(from *Program, prog *Program, config *OuroborosConfig, visited map[string]bool, flowchart *strings.Builder) {
	var nextFrom *Program
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

	progSpec, err := ebpf.LoadCollectionSpec(filepath.Join("target", fmt.Sprintf("%s.o", prog.Name)))
	if err != nil {
		Fatal("Failed to load program object", "program", prog.Name, "error", err)
	}

	var nextProgs []*Program
	for _, p := range progSpec.Programs {
		insns := p.Instructions
		for i, ins := range insns {
			if ins.OpCode.JumpOp() == asm.Call && ins.Constant == int64(asm.FnTailCall) {
				if i > 0 && insns[i-1].OpCode.ALUOp() == asm.Mov && insns[i-1].Dst == asm.R3 {
					mapIndex := insns[i-1].Constant
					for j := range config.Programs {
						if config.Programs[j].ID == int(mapIndex) {
							nextProgs = append(nextProgs, &config.Programs[j])
						}
					}
				}
			}
		}
	}

	for _, nextProg := range nextProgs {
		analyzeProgram(nextFrom, nextProg, config, visited, flowchart)
	}
}

