package cmd

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/spf13/cobra"
)

var mergeCmd = &cobra.Command{
	Use:   "merge [src] [target]",
	Short: "Merge eBPF tail call targets into a single object file, replacing tail calls with direct jumps",
	Long: `Merge eBPF programs:
  ouroboros merge              - Merge all programs into the main program (defined in config)
  ouroboros merge [src] [target] - Merge target program into src program`,
	Args: cobra.RangeArgs(0, 2),
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

		var srcProg *Program
		var targetProg *Program

		switch len(args) {
		case 0:
			// No arguments: merge all into main program
			srcProg = ouroborosConfig.GetMainProgram()
			if srcProg == nil {
				fmt.Println("No main program defined in ouroboros.json")
				fmt.Println("Please set 'is_main: true' for one program or specify programs explicitly")
				os.Exit(1)
			}
			fmt.Printf("Using main program '%s' as merge target\n", srcProg.Name)

		case 2:
			// Two arguments: merge target into src
			srcName := args[0]
			targetName := args[1]

			// Find src program
			for i := range ouroborosConfig.Programs {
				if ouroborosConfig.Programs[i].Name == srcName {
					srcProg = &ouroborosConfig.Programs[i]
					break
				}
			}
			if srcProg == nil {
				fmt.Printf("Source program '%s' not found in ouroboros.json\n", srcName)
				os.Exit(1)
			}

			// Find target program
			for i := range ouroborosConfig.Programs {
				if ouroborosConfig.Programs[i].Name == targetName {
					targetProg = &ouroborosConfig.Programs[i]
					break
				}
			}
			if targetProg == nil {
				fmt.Printf("Target program '%s' not found in ouroboros.json\n", targetName)
				os.Exit(1)
			}

		default:
			fmt.Println("Invalid usage. Use:")
			fmt.Println("  ouroboros merge              - Merge all programs into main program")
			fmt.Println("  ouroboros merge [src] [target] - Merge target into src")
			os.Exit(1)
		}

		// Build all programs first
		buildCmd.Run(cmd, []string{})

		fmt.Printf("Analyzing tail calls in %s...\n", srcProg.Name)

		// Analyze and merge
		mergedObjectPath := filepath.Join(targetDir, fmt.Sprintf("%s.merged.o", srcProg.Name))

		if targetProg != nil {
			// Specific merge: src + target
			mergeTwoPrograms(srcProg, targetProg, ouroborosConfig, mergedObjectPath)
		} else {
			// Full merge: src + all its tail call targets
			mergeProgram(srcProg, ouroborosConfig, mergedObjectPath)
		}

		fmt.Printf("Merged object created at %s\n", mergedObjectPath)
	},
}

type TailCallInfo struct {
	InstructionIndex int
	TargetProgramID  int
	TargetProgram    *Program
}

func mergeTwoPrograms(srcProg *Program, targetProg *Program, config *OuroborosConfig, outputPath string) {
	fmt.Printf("Merging %s into %s...\n", targetProg.Name, srcProg.Name)

	objectsToMerge := []string{
		filepath.Join(targetDir, fmt.Sprintf("%s.o", srcProg.Name)),
		filepath.Join(targetDir, fmt.Sprintf("%s.o", targetProg.Name)),
	}

	fmt.Printf("Merging 2 object files:\n")
	for _, obj := range objectsToMerge {
		fmt.Printf("  - %s\n", obj)
	}

	// Link objects together
	linkObjects(objectsToMerge, outputPath)

	// Replace tail calls with jumps in the merged object
	replaceTailCallsWithJumps(outputPath, srcProg, config)
}

func mergeProgram(prog *Program, config *OuroborosConfig, outputPath string) {
	visited := make(map[string]bool)
	objectsToMerge := []string{}

	// Collect all tail call targets recursively
	collectTailCallTargets(prog, config, visited, &objectsToMerge)

	fmt.Printf("Found %d object files to merge\n", len(objectsToMerge))
	for _, obj := range objectsToMerge {
		fmt.Printf("  - %s\n", obj)
	}

	// Link all objects together
	if len(objectsToMerge) == 0 {
		fmt.Println("No tail calls found, nothing to merge")
		return
	}

	linkObjects(objectsToMerge, outputPath)

	// Replace tail calls with jumps in the merged object
	replaceTailCallsWithJumps(outputPath, prog, config)
}

func collectTailCallTargets(prog *Program, config *OuroborosConfig, visited map[string]bool, objectsToMerge *[]string) {
	if visited[prog.Name] {
		return
	}
	visited[prog.Name] = true

	objectPath := filepath.Join(targetDir, fmt.Sprintf("%s.o", prog.Name))
	*objectsToMerge = append(*objectsToMerge, objectPath)

	// Load the program to analyze tail calls
	progSpec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		fmt.Printf("Failed to load program object %s: %v\n", prog.Name, err)
		os.Exit(1)
	}

	// Analyze instructions for tail calls
	for _, p := range progSpec.Programs {
		insns := p.Instructions
		for i, ins := range insns {
			// Check for bpf_tail_call pattern (same as flow.go:85-94)
			if ins.OpCode.JumpOp() == asm.Call && ins.Constant == int64(asm.FnTailCall) {
				if i > 0 && insns[i-1].OpCode.ALUOp() == asm.Mov && insns[i-1].Dst == asm.R3 {
					mapIndex := insns[i-1].Constant
					for j := range config.Programs {
						if config.Programs[j].ID == int(mapIndex) {
							fmt.Printf("  Found tail call: %s -> %s (ID: %d)\n", prog.Name, config.Programs[j].Name, mapIndex)
							// Recursively collect targets
							collectTailCallTargets(&config.Programs[j], config, visited, objectsToMerge)
						}
					}
				}
			}
		}
	}
}

// deduplicateMapSymbols removes duplicate symbols from object files
// keeping only definitions from the first file
func deduplicateMapSymbols(objectPaths []string) ([]string, error) {
	if len(objectPaths) <= 1 {
		return objectPaths, nil
	}

	fmt.Println("Deduplicating symbols...")

	// First file is the source - keep all its symbols
	seenSymbols := make(map[string]bool)

	// Read symbols from first file
	firstData, err := os.ReadFile(objectPaths[0])
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", objectPaths[0], err)
	}

	firstElf, err := elf.NewFile(bytes.NewReader(firstData))
	if err != nil {
		return nil, fmt.Errorf("failed to parse ELF %s: %w", objectPaths[0], err)
	}

	firstSymbols, err := firstElf.Symbols()
	if err != nil {
		firstElf.Close()
		return nil, fmt.Errorf("failed to read symbols from %s: %w", objectPaths[0], err)
	}

	// Track all global symbols from first file
	for _, sym := range firstSymbols {
		if sym.Name != "" && elf.ST_BIND(sym.Info) == elf.STB_GLOBAL {
			seenSymbols[sym.Name] = true
		}
	}
	firstElf.Close()

	fmt.Printf("  Source file %s: keeping all %d global symbols\n", filepath.Base(objectPaths[0]), len(seenSymbols))

	dedupedPaths := make([]string, 0, len(objectPaths))
	dedupedPaths = append(dedupedPaths, objectPaths[0]) // Keep first as-is

	// Process remaining files
	for _, objPath := range objectPaths[1:] {
		data, err := os.ReadFile(objPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", objPath, err)
		}

		elfFile, err := elf.NewFile(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("failed to parse ELF %s: %w", objPath, err)
		}

		symbols, err := elfFile.Symbols()
		if err != nil {
			elfFile.Close()
			return nil, fmt.Errorf("failed to read symbols from %s: %w", objPath, err)
		}

		// Find duplicate global symbols
		duplicates := []string{}
		for _, sym := range symbols {
			if sym.Name != "" && elf.ST_BIND(sym.Info) == elf.STB_GLOBAL {
				if seenSymbols[sym.Name] {
					duplicates = append(duplicates, sym.Name)
				}
			}
		}
		elfFile.Close()

		if len(duplicates) == 0 {
			// No duplicates, use original
			dedupedPaths = append(dedupedPaths, objPath)
			fmt.Printf("  %s: no duplicate symbols\n", filepath.Base(objPath))
			continue
		}

		// Create modified copy with duplicates removed
		fmt.Printf("  %s: removing %d duplicate symbols\n", filepath.Base(objPath), len(duplicates))
		tempPath := objPath + ".dedup.o"
		if err := removeSymbolsFromELF(objPath, tempPath, duplicates); err != nil {
			return nil, fmt.Errorf("failed to remove symbols from %s: %w", objPath, err)
		}

		dedupedPaths = append(dedupedPaths, tempPath)
	}

	return dedupedPaths, nil
}

// removeSymbolsFromELF removes map definitions by zeroing out their data in .maps section
// and converting symbols to extern references
func removeSymbolsFromELF(inputPath, outputPath string, symbolsToRemove []string) error {
	// Read the ELF file
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	elfFile, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer elfFile.Close()

	// Find .maps section
	mapsSection := elfFile.Section(".maps")
	if mapsSection == nil {
		// No maps section, just copy
		return os.WriteFile(outputPath, data, 0644)
	}

	// Get symbols
	symbols, err := elfFile.Symbols()
	if err != nil {
		return err
	}

	// Find the offset and size of each duplicate map in .maps section
	for _, sym := range symbols {
		for _, symName := range symbolsToRemove {
			if sym.Name == symName && sym.Section == elf.SectionIndex(mapsSection.SectionIndex) {
				// Zero out this map's data in .maps section
				mapOffset := mapsSection.Offset + sym.Value
				mapSize := sym.Size

				for i := uint64(0); i < mapSize; i++ {
					data[mapOffset+i] = 0
				}
				fmt.Printf("    Zeroed map '%s' at offset %d, size %d\n", symName, mapOffset, mapSize)
			}
		}
	}

	// Write modified ELF
	return os.WriteFile(outputPath, data, 0644)
}

func linkObjects(objectPaths []string, outputPath string) {
	fmt.Printf("Linking %d objects into %s...\n", len(objectPaths), outputPath)

	// Deduplicate map symbols before linking
	dedupedPaths, err := deduplicateMapSymbols(objectPaths)
	if err != nil {
		fmt.Printf("Failed to deduplicate map symbols: %v\n", err)
		os.Exit(1)
	}

	// Use bpftool to link BPF object files
	// bpftool gen object <output> <input1.o> <input2.o> ...
	args := []string{"gen", "object", outputPath}
	args = append(args, dedupedPaths...)

	linkCmd := exec.Command("bpftool", args...)
	linkCmd.Stdout = os.Stdout
	linkCmd.Stderr = os.Stderr
	if err := linkCmd.Run(); err != nil {
		fmt.Printf("bpftool linking failed: %v\n", err)
		fmt.Println("Please ensure bpftool is installed and available in PATH")
		os.Exit(1)
	}

	// Clean up temporary deduplicated files
	for _, path := range dedupedPaths {
		if path != outputPath {
			os.Remove(path)
		}
	}

	fmt.Println("Linking complete.")
}

func replaceTailCallsWithJumps(objectPath string, prog *Program, config *OuroborosConfig) {
	fmt.Printf("Replacing tail calls with direct jumps in %s...\n", objectPath)

	// Load the merged object
	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		fmt.Printf("Failed to load merged object: %v\n", err)
		os.Exit(1)
	}

	modified := false

	// Process each program in the collection
	for progName, progSpec := range spec.Programs {
		insns := progSpec.Instructions
		patchedInsns := make(asm.Instructions, 0, len(insns))
		i := 0

		for i < len(insns) {
			ins := insns[i]

			// Check for tail call pattern: mov r3, <id>; call bpf_tail_call
			if i+1 < len(insns) &&
				ins.OpCode.ALUOp() == asm.Mov &&
				ins.Dst == asm.R3 &&
				insns[i+1].OpCode.JumpOp() == asm.Call &&
				insns[i+1].Constant == int64(asm.FnTailCall) {

				mapIndex := ins.Constant
				var targetProg *Program
				for j := range config.Programs {
					if config.Programs[j].ID == int(mapIndex) {
						targetProg = &config.Programs[j]
						break
					}
				}

				if targetProg != nil {
					targetEntrypoint := targetProg.Entrypoint
					if targetEntrypoint == "" {
						targetEntrypoint = targetProg.Name
					}

					// Check if target exists in merged object
					if _, exists := spec.Programs[targetEntrypoint]; exists {
						fmt.Printf("  Replacing tail call in %s -> %s with direct jump\n",
							progName, targetEntrypoint)

						// Replace mov r3 with NOP
						nopInsn := asm.Instruction{
							OpCode: asm.OpCode(asm.ALUClass).SetALUOp(asm.Mov),
							Dst:    asm.R0,
							Src:    asm.R0,
						}
						patchedInsns = append(patchedInsns, nopInsn)

						// Replace bpf_tail_call with direct jump (goto)
						// Tail calls don't return, so use JA (jump always) instead of call
						jumpInsn := asm.Instruction{
							OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Ja),
							Offset: 0, // Will be resolved by the linker/loader
						}.WithSymbol(targetEntrypoint)

						patchedInsns = append(patchedInsns, jumpInsn)
						modified = true

						// Skip the original mov + call instructions
						i += 2
						continue
					} else {
						fmt.Printf("  Warning: Target '%s' not found, keeping tail call\n", targetEntrypoint)
					}
				}
			}

			// Keep original instruction if not a tail call
			patchedInsns = append(patchedInsns, ins)
			i++
		}

		// Update the program's instructions
		if modified {
			progSpec.Instructions = patchedInsns
		}
	}

	if !modified {
		fmt.Println("No tail calls found to replace")
		return
	}

	// Write the modified spec back to disk
	if err := writeCollectionSpec(spec, objectPath); err != nil {
		fmt.Printf("Failed to write modified object: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Tail call replacement complete!")
}

func writeCollectionSpec(spec *ebpf.CollectionSpec, outputPath string) error {
	fmt.Println("Writing modified bytecode to ELF file...")

	// Read the original ELF file
	originalData, err := os.ReadFile(outputPath)
	if err != nil {
		return fmt.Errorf("failed to read original ELF: %w", err)
	}

	elfFile, err := elf.NewFile(bytes.NewReader(originalData))
	if err != nil {
		return fmt.Errorf("failed to parse ELF: %w", err)
	}
	defer elfFile.Close()

	// Patch each program section with modified instructions
	for progName, progSpec := range spec.Programs {
		// Find the corresponding ELF section
		sectionName := progSpec.SectionName
		section := elfFile.Section(sectionName)
		if section == nil {
			fmt.Printf("  Warning: Section '%s' not found for program '%s'\n", sectionName, progName)
			continue
		}

		// Encode the modified instructions to bytecode
		var buf bytes.Buffer

		for _, ins := range progSpec.Instructions {
			// Each BPF instruction is 8 bytes
			// Format: opcode (1 byte) + dst_src (1 byte) + offset (2 bytes) + imm (4 bytes)
			insBytes := make([]byte, 8)
			insBytes[0] = byte(ins.OpCode)
			insBytes[1] = byte(ins.Dst&0xf) | byte((ins.Src&0xf)<<4)
			binary.LittleEndian.PutUint16(insBytes[2:4], uint16(ins.Offset))
			binary.LittleEndian.PutUint32(insBytes[4:8], uint32(ins.Constant))

			buf.Write(insBytes)
		}

		patchedBytecode := buf.Bytes()
		fmt.Printf("  Patched section '%s' (%d instructions, %d bytes)\n",
			sectionName, len(progSpec.Instructions), len(patchedBytecode))

		// Modify the ELF file in memory by patching the section data
		// This requires reconstructing the ELF file with modified sections
		if err := patchELFSection(outputPath, sectionName, patchedBytecode); err != nil {
			return fmt.Errorf("failed to patch section '%s': %w", sectionName, err)
		}
	}

	return nil
}

func patchELFSection(elfPath string, sectionName string, newData []byte) error {
	// Read the original file
	data, err := os.ReadFile(elfPath)
	if err != nil {
		return err
	}

	elfFile, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer elfFile.Close()

	section := elfFile.Section(sectionName)
	if section == nil {
		return fmt.Errorf("section not found: %s", sectionName)
	}

	// Check if new data fits in the existing section
	if uint64(len(newData)) > section.Size {
		return fmt.Errorf("new data (%d bytes) exceeds section size (%d bytes)",
			len(newData), section.Size)
	}

	// Patch the data at the section offset
	offset := section.Offset
	copy(data[offset:offset+uint64(len(newData))], newData)

	// If new data is smaller, zero out remaining bytes
	if uint64(len(newData)) < section.Size {
		remaining := data[offset+uint64(len(newData)) : offset+section.Size]
		for i := range remaining {
			remaining[i] = 0
		}
	}

	// Write back to file
	return os.WriteFile(elfPath, data, 0644)
}

func init() {
	RootCmd.AddCommand(mergeCmd)
}