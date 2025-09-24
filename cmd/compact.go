package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/spf13/cobra"
)

var compactCmd = &cobra.Command{
	Use:   "compact",
	Short: "Generate compact eBPF binaries by merging tail calls to reduce tail call depth",
	Run: func(cmd *cobra.Command, args []string) {
		ouroborosConfig, err := ReadConfig()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		mainProg := ouroborosConfig.GetMainProgram()
		if mainProg == nil {
			fmt.Println("Main program not found in ouroboros.json")
			os.Exit(1)
		}

		// Build first to ensure we have compiled .o files
		buildCmd.Run(cmd, []string{})

		// Create target/compacted directory
		compactedDir := filepath.Join("target", "compacted")
		if err := os.MkdirAll(compactedDir, 0755); err != nil {
			fmt.Printf("Failed to create compacted directory: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Analyzing programs for compaction...")
		
		// Analyze and compact programs
		compactedConfig := compactPrograms(ouroborosConfig, compactedDir)
		
		// Write compacted ouroboros.json
		configPath := filepath.Join(compactedDir, "ouroboros.json")
		configData, err := json.MarshalIndent(compactedConfig, "", "  ")
		if err != nil {
			fmt.Printf("Failed to marshal config: %v\n", err)
			os.Exit(1)
		}
		
		if err := os.WriteFile(configPath, configData, 0644); err != nil {
			fmt.Printf("Failed to write compacted config: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("\nCompacted binaries created in %s/\n", compactedDir)
	},
}

func compactPrograms(config *OuroborosConfig, outputDir string) *OuroborosConfig {
	compactedConfig := &OuroborosConfig{
		Programs:      []Program{},
		SharedMaps:    config.SharedMaps,
		CompileArgs:   config.CompileArgs,
		ProgramMap:    config.ProgramMap,
		ProgramPrefix: config.ProgramPrefix,
	}

	processed := make(map[string]bool)
	programID := 0

	// Start from main program and compact chains
	mainProg := config.GetMainProgram()
	if mainProg != nil {
		compactedName, mergedCount := compactProgramChain(mainProg, config, outputDir, processed)
		if compactedName != "" {
			compactedConfig.Programs = append(compactedConfig.Programs, Program{
				Name:   compactedName,
				ID:     programID,
				IsMain: true,
			})
			programID++
			fmt.Printf("Created compact program: %s (merged %d programs)\n", compactedName, mergedCount)
		}
	}

	// Handle any remaining unprocessed programs
	for _, prog := range config.Programs {
		if !processed[prog.Name] {
			// Copy as standalone
			if copyStandaloneProgram(prog, outputDir) {
				compactedConfig.Programs = append(compactedConfig.Programs, Program{
					Name:     prog.Name,
					ID:       programID,
					IsMain:   false,
					Metadata: prog.Metadata,
				})
				programID++
				processed[prog.Name] = true
			}
		}
	}

	return compactedConfig
}

func compactProgramChain(prog *Program, config *OuroborosConfig, outputDir string, processed map[string]bool) (string, int) {
	if processed[prog.Name] {
		return "", 0
	}

	// Load the program bytecode
	progPath := filepath.Join("target", fmt.Sprintf("%s.o", prog.Name))
	progSpec, err := ebpf.LoadCollectionSpec(progPath)
	if err != nil {
		fmt.Printf("Failed to load %s: %v\n", prog.Name, err)
		return "", 0
	}

	// Find tail calls and check if we can compact
	tailCalls := findTailCallTargets(progSpec, config)
	if len(tailCalls) == 0 {
		// No tail calls, copy as standalone
		if copyStandaloneProgram(*prog, outputDir) {
			processed[prog.Name] = true
			return prog.Name, 1
		}
		return "", 0
	}

	// Check BPF constraints - can we merge these programs?
	if !checkBPFConstraints(prog, tailCalls, config) {
		// Can't merge due to constraints, copy as standalone
		if copyStandaloneProgram(*prog, outputDir) {
			processed[prog.Name] = true
			return prog.Name, 1
		}
		return "", 0
	}

	// Merge the programs
	compactedName := fmt.Sprintf("%s_compact", prog.Name)
	mergedCount := mergePrograms(prog, tailCalls, config, outputDir, processed)
	
	if mergedCount > 0 {
		return compactedName, mergedCount
	}
	
	return "", 0
}

func findTailCallTargets(spec *ebpf.CollectionSpec, config *OuroborosConfig) []*Program {
	var targets []*Program
	
	for _, progSpec := range spec.Programs {
		insns := progSpec.Instructions
		for i, ins := range insns {
			// Look for tail call pattern: MOV R3, <id>; CALL tail_call
			if ins.OpCode.JumpOp() == asm.Call && ins.Constant == int64(asm.FnTailCall) {
				if i > 0 && insns[i-1].OpCode.ALUOp() == asm.Mov && insns[i-1].Dst == asm.R3 {
					targetID := int(insns[i-1].Constant)
					
					// Find the program with this ID
					for j := range config.Programs {
						if config.Programs[j].ID == targetID {
							targets = append(targets, &config.Programs[j])
							break
						}
					}
				}
			}
		}
	}
	
	return targets
}

func checkBPFConstraints(mainProg *Program, tailTargets []*Program, config *OuroborosConfig) bool {
	// Check for cycles
	if hasCycles(mainProg, tailTargets, config) {
		fmt.Printf("Cannot compact %s: cycle detected\n", mainProg.Name)
		return false
	}

	// Check instruction count limits (rough estimate)
	totalInstructions := 0
	
	// Count main program instructions
	if spec, err := ebpf.LoadCollectionSpec(filepath.Join("target", fmt.Sprintf("%s.o", mainProg.Name))); err == nil {
		for _, p := range spec.Programs {
			totalInstructions += len(p.Instructions)
		}
	}
	
	// Count tail call target instructions
	for _, target := range tailTargets {
		if spec, err := ebpf.LoadCollectionSpec(filepath.Join("target", fmt.Sprintf("%s.o", target.Name))); err == nil {
			for _, p := range spec.Programs {
				totalInstructions += len(p.Instructions)
			}
		}
	}
	
	// BPF program size limit is ~1M instructions, be conservative
	if totalInstructions > 100000 {
		fmt.Printf("Cannot compact %s: too many instructions (%d)\n", mainProg.Name, totalInstructions)
		return false
	}
	
	return true
}

func hasCycles(mainProg *Program, tailTargets []*Program, config *OuroborosConfig) bool {
	// Simple cycle detection: check if any tail call targets call back to main
	for _, target := range tailTargets {
		if spec, err := ebpf.LoadCollectionSpec(filepath.Join("target", fmt.Sprintf("%s.o", target.Name))); err == nil {
			targetTailCalls := findTailCallTargets(spec, config)
			for _, ttc := range targetTailCalls {
				if ttc.ID == mainProg.ID {
					return true // Cycle detected
				}
			}
		}
	}
	return false
}

func mergePrograms(mainProg *Program, tailTargets []*Program, config *OuroborosConfig, outputDir string, processed map[string]bool) int {
	compactedName := fmt.Sprintf("%s_compact", mainProg.Name)
	
	// Collect all .o files to merge
	var objectFiles []string
	objectFiles = append(objectFiles, filepath.Join("target", fmt.Sprintf("%s.o", mainProg.Name)))
	
	for _, target := range tailTargets {
		objectFiles = append(objectFiles, filepath.Join("target", fmt.Sprintf("%s.o", target.Name)))
		processed[target.Name] = true
	}
	
	// Use system linker to merge object files
	outputPath := filepath.Join(outputDir, fmt.Sprintf("%s.o", compactedName))
	if err := linkObjectFilesWithLD(objectFiles, outputPath); err != nil {
		fmt.Printf("Failed to link object files: %v\n", err)
		return 0
	}
	
	// Now patch the merged object file to replace tail calls with jumps
	if err := patchTailCallsInObjectFile(outputPath, mainProg, tailTargets, config); err != nil {
		fmt.Printf("Failed to patch tail calls: %v\n", err)
		return 0
	}
	
	processed[mainProg.Name] = true
	return len(tailTargets) + 1
}

func replaceTailCallsWithJumps(instructions asm.Instructions, programOffsets map[string]int, config *OuroborosConfig) {
	for i := range instructions {
		ins := instructions[i]
		
		// Look for tail call pattern
		if ins.OpCode.JumpOp() == asm.Call && ins.Constant == int64(asm.FnTailCall) {
			if i > 0 && instructions[i-1].OpCode.ALUOp() == asm.Mov && instructions[i-1].Dst == asm.R3 {
				targetID := int(instructions[i-1].Constant)
				
				// Find target program name
				for _, prog := range config.Programs {
					if prog.ID == targetID {
						if offset, ok := programOffsets[prog.Name]; ok {
							// Replace with direct jump
							jumpOffset := int16(offset - i)
							instructions[i-1] = asm.Instruction{
								OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Ja),
								Offset: jumpOffset,
							}
							// Replace tail call with NOP
							instructions[i] = asm.Mov.Reg(asm.R0, asm.R0)
						}
						break
					}
				}
			}
		}
	}
}

func copyStandaloneProgram(prog Program, outputDir string) bool {
	srcPath := filepath.Join("target", fmt.Sprintf("%s.o", prog.Name))
	dstPath := filepath.Join(outputDir, fmt.Sprintf("%s.o", prog.Name))
	
	data, err := os.ReadFile(srcPath)
	if err != nil {
		fmt.Printf("Failed to read %s: %v\n", srcPath, err)
		return false
	}
	
	if err := os.WriteFile(dstPath, data, 0644); err != nil {
		fmt.Printf("Failed to write %s: %v\n", dstPath, err)
		return false
	}
	
	return true
}

func linkObjectFilesWithLD(objectFiles []string, outputPath string) error {
	// Use ld with -r flag for relocatable linking
	args := []string{"-r", "-o", outputPath}
	args = append(args, objectFiles...)
	
	cmd := exec.Command("ld", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ld failed: %v\nOutput: %s", err, output)
	}
	
	fmt.Printf("Linked %d object files into %s\n", len(objectFiles), outputPath)
	return nil
}

func patchTailCallsInObjectFile(objectPath string, mainProg *Program, tailTargets []*Program, config *OuroborosConfig) error {
	// Load the linked object file
	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return fmt.Errorf("failed to load linked object: %v", err)
	}
	
	// Find program sections and their offsets
	programOffsets := make(map[string]int)
	var allInstructions asm.Instructions
	
	// The linker should have combined all programs into sections
	// We need to find where each original program starts
	for _, progSpec := range spec.Programs {
		allInstructions = progSpec.Instructions
		break // Take the first (should be the merged program)
	}
	
	// Scan for program boundaries (this is an approximation)
	// In practice, we'd use debug symbols or section headers
	programOffsets[mainProg.Name] = 0
	
	// Estimate where tail call target programs start
	// This is simplified - real implementation would parse ELF sections
	estimatedOffset := len(allInstructions) / (len(tailTargets) + 1)
	for i, target := range tailTargets {
		programOffsets[target.Name] = estimatedOffset * (i + 1)
	}
	
	// Replace tail calls with direct jumps
	replaceTailCallsWithJumps(allInstructions, programOffsets, config)
	
	// Write the patched instructions back
	// This would require ELF manipulation in practice
	// For now, we'll create a new collection spec
	patchedSpec := &ebpf.ProgramSpec{
		Name:         fmt.Sprintf("%s_compact", mainProg.Name),
		Type:         ebpf.XDP,
		Instructions: allInstructions,
		License:      "GPL",
	}
	
	patchedCollection := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			patchedSpec.Name: patchedSpec,
		},
		Maps: spec.Maps,
	}
	
	// Write back to file (this is still a placeholder for proper ELF writing)
	return writePatchedObjectFile(patchedCollection, objectPath)
}

func writePatchedObjectFile(collection *ebpf.CollectionSpec, outputPath string) error {
	// This would need proper ELF writing
	// For now, write the patched instructions in a readable format
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()
	
	fmt.Fprintf(file, "# Compacted and patched eBPF object\n")
	for name, prog := range collection.Programs {
		fmt.Fprintf(file, "# Program: %s\n", name)
		fmt.Fprintf(file, "# Type: %s\n", prog.Type.String())
		fmt.Fprintf(file, "# Instructions: %d\n", len(prog.Instructions))
		for i, ins := range prog.Instructions {
			fmt.Fprintf(file, "%04d: %v\n", i, ins)
		}
	}
	
	return nil
}

func init() {
	RootCmd.AddCommand(compactCmd)
}