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
			fmt.Println("libbpf-dev is not installed. Please install it first.")
			os.Exit(1)
		}

		ouroborosConfig, err := ReadConfig()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		mainProg := ouroborosConfig.GetMainProgram()
		if mainProg == nil {
			fmt.Println("Main program not found in ouroboros.json. Please set 'is_main' to true for one of the programs.")
			os.Exit(1)
		}

		buildCmd.Run(cmd, []string{})

		outputFile := "flow.mermaid"
		if len(args) > 0 {
			outputFile = args[0]
		}

		f, err := os.Create(outputFile)
		if err != nil {
			fmt.Printf("Failed to create output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()

		fmt.Println("Analyzing flow...")
		var flowchart strings.Builder
		flowchart.WriteString("graph TD\n")
		analyzeProgram(nil, mainProg, ouroborosConfig, make(map[string]bool), &flowchart)
		fmt.Fprint(f, flowchart.String())
		fmt.Printf("Flowchart generated at %s\n", outputFile)
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
		fmt.Printf("Failed to load program object %s: %v\n", prog.Name, err)
		os.Exit(1)
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

func init() {
	RootCmd.AddCommand(flowCmd)
}
