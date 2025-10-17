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
				fmt.Printf("    Checking symbol '%s': duplicate=%v\n", sym.Name, seenSymbols[sym.Name])
				if seenSymbols[sym.Name] {
					duplicates = append(duplicates, sym.Name)
				} else {
					// Track this symbol for future files
					seenSymbols[sym.Name] = true
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

// removeSymbolsFromELF removes duplicate map definitions from the .maps section and BTF
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

	// Get symbols
	symbols, err := elfFile.Symbols()
	if err != nil {
		return err
	}

	// Find .maps section
	var mapsSection *elf.Section
	var mapsSectionIndex int
	for i, section := range elfFile.Sections {
		if section.Name == ".maps" {
			mapsSection = section
			mapsSectionIndex = i
			break
		}
	}

	if mapsSection == nil {
		// No .maps section, just copy
		return os.WriteFile(outputPath, data, 0644)
	}

	// Find which map symbols to remove
	mapsToRemove := make(map[string]bool)
	for _, symName := range symbolsToRemove {
		mapsToRemove[symName] = true
	}

	// Build list of map symbols with their offsets and sizes
	type mapInfo struct {
		name   string
		offset uint64
		size   uint64
		symIdx int
	}

	mapList := []mapInfo{}
	for i, sym := range symbols {
		if sym.Section == elf.SectionIndex(mapsSectionIndex) && elf.ST_TYPE(sym.Info) == elf.STT_OBJECT {
			mapList = append(mapList, mapInfo{
				name:   sym.Name,
				offset: sym.Value,
				size:   sym.Size,
				symIdx: i,
			})
		}
	}

	// Sort by offset to process in order
	for i := 0; i < len(mapList); i++ {
		for j := i + 1; j < len(mapList); j++ {
			if mapList[j].offset < mapList[i].offset {
				mapList[i], mapList[j] = mapList[j], mapList[i]
			}
		}
	}

	// Remove duplicate maps from .maps section data
	mapsData, err := mapsSection.Data()
	if err != nil {
		return err
	}

	newMapsData := []byte{}
	removedMaps := make(map[string]uint64) // name -> new offset

	for _, m := range mapList {
		if mapsToRemove[m.name] {
			// Skip this map definition - don't copy to newMapsData
			fmt.Printf("    Removing map '%s' from .maps section (offset %d, size %d)\n",
				m.name, m.offset, m.size)
			continue
		}

		// Keep this map
		removedMaps[m.name] = uint64(len(newMapsData))
		mapBytes := mapsData[m.offset : m.offset+m.size]
		newMapsData = append(newMapsData, mapBytes...)
	}

	// Update .maps section data
	if uint64(len(newMapsData)) > mapsSection.Size {
		return fmt.Errorf("new .maps data too large: %d > %d", len(newMapsData), mapsSection.Size)
	}

	// Write new .maps data
	mapsSectionOffset := mapsSection.Offset
	copy(data[mapsSectionOffset:], newMapsData)

	// Zero out remaining space
	if uint64(len(newMapsData)) < mapsSection.Size {
		remaining := data[mapsSectionOffset+uint64(len(newMapsData)) : mapsSectionOffset+mapsSection.Size]
		for i := range remaining {
			remaining[i] = 0
		}
	}

	// Update .maps section size in section header
	shoff := binary.LittleEndian.Uint64(data[40:48])
	mapsSectionHeaderOffset := shoff + uint64(mapsSectionIndex)*64
	shSizeOffset := mapsSectionHeaderOffset + 32
	binary.LittleEndian.PutUint64(data[shSizeOffset:shSizeOffset+8], uint64(len(newMapsData)))

	fmt.Printf("    Resized .maps section from %d to %d bytes\n", mapsSection.Size, len(newMapsData))

	// Remove duplicate map symbols from symbol table
	symtabSection := elfFile.Section(".symtab")
	if symtabSection != nil {
		symtabOffset := symtabSection.Offset
		symEntrySize := uint64(24)

		// Mark symbols for removal and update offsets for kept symbols
		for i, sym := range symbols {
			if sym.Section == elf.SectionIndex(mapsSectionIndex) && elf.ST_TYPE(sym.Info) == elf.STT_OBJECT {
				if mapsToRemove[sym.Name] {
					// Zero out this symbol entry
					entryOffset := symtabOffset + uint64(i+1)*symEntrySize
					for j := uint64(0); j < symEntrySize; j++ {
						data[entryOffset+j] = 0
					}
					fmt.Printf("    Removed symbol '%s' (index %d)\n", sym.Name, i+1)
				} else if newOffset, ok := removedMaps[sym.Name]; ok {
					// Update symbol value (offset) to new location
					entryOffset := symtabOffset + uint64(i+1)*symEntrySize
					valueOffset := entryOffset + 8 // st_value is at offset 8
					binary.LittleEndian.PutUint64(data[valueOffset:valueOffset+8], newOffset)
				}
			}
		}
	}

	// Write modified ELF
	return os.WriteFile(outputPath, data, 0644)
}

func linkObjects(objectPaths []string, outputPath string) {
	fmt.Printf("Merging %d programs at LLVM IR level...\n", len(objectPaths))

	// Step 1: Compile each object's source to LLVM IR
	irPaths := []string{}
	config, _ := ReadConfig()

	for _, objPath := range objectPaths {
		// Get program name from object path (e.g., target/main.o -> main)
		progName := filepath.Base(objPath)
		progName = progName[:len(progName)-2] // Remove .o extension

		// Find the program in config
		var prog *Program
		for i := range config.Programs {
			if config.Programs[i].Name == progName {
				prog = &config.Programs[i]
				break
			}
		}

		if prog == nil {
			fmt.Printf("Warning: Program %s not found in config\n", progName)
			continue
		}

		progDir := filepath.Join(srcDir, progName)
		mainC := filepath.Join(progDir, entryPointFile)
		outputLL := filepath.Join(targetDir, fmt.Sprintf("%s.ll", progName))

		fmt.Printf("  Compiling %s to LLVM IR...\n", progName)

		// Compile to LLVM IR with -S -emit-llvm
		args := []string{"-O2", "-g", "-target", "bpf", "-S", "-emit-llvm", mainC, "-o", outputLL, "-Isrc/"}
		args = append(args, config.CompileArgs...)

		clangCmd := exec.Command("clang", args...)
		clangCmd.Stdout = os.Stdout
		clangCmd.Stderr = os.Stderr
		if err := clangCmd.Run(); err != nil {
			fmt.Printf("Failed to compile %s to LLVM IR: %v\n", progName, err)
			os.Exit(1)
		}

		irPaths = append(irPaths, outputLL)
	}

	// Step 2: Deduplicate globals in IR files
	fmt.Println("  Deduplicating globals in LLVM IR...")
	if err := deduplicateIRGlobals(irPaths); err != nil {
		fmt.Printf("Failed to deduplicate IR globals: %v\n", err)
		os.Exit(1)
	}

	// Step 3: Link LLVM IR files
	mergedLL := outputPath[:len(outputPath)-2] + ".ll" // Replace .o with .ll
	fmt.Printf("  Linking %d LLVM IR files...\n", len(irPaths))

	linkArgs := []string{"-S", "-o", mergedLL}
	linkArgs = append(linkArgs, irPaths...)

	llvmLinkCmd := exec.Command("llvm-link", linkArgs...)
	llvmLinkCmd.Stdout = os.Stdout
	llvmLinkCmd.Stderr = os.Stderr
	if err := llvmLinkCmd.Run(); err != nil {
		fmt.Printf("llvm-link failed: %v\n", err)
		fmt.Println("Please ensure llvm-link is installed and available in PATH")
		os.Exit(1)
	}

	// Step 3: Compile merged LLVM IR to eBPF object
	fmt.Printf("  Compiling merged LLVM IR to eBPF object...\n")

	compileArgs := []string{"-O2", "-g", "-target", "bpf", "-c", mergedLL, "-o", outputPath}
	compileArgs = append(compileArgs, config.CompileArgs...)

	clangCmd := exec.Command("clang", compileArgs...)
	clangCmd.Stdout = os.Stdout
	clangCmd.Stderr = os.Stderr
	if err := clangCmd.Run(); err != nil {
		fmt.Printf("Failed to compile merged LLVM IR: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("LLVM IR merge complete.")
}

// deduplicateIRGlobals converts duplicate global definitions to extern declarations
func deduplicateIRGlobals(irPaths []string) error {
	seenGlobals := make(map[string]bool)

	for idx, irPath := range irPaths {
		// Read IR file
		data, err := os.ReadFile(irPath)
		if err != nil {
			return err
		}

		lines := bytes.Split(data, []byte("\n"))
		modified := false

		for i, line := range lines {
			// Look for global variable definitions
			// Example: @hs_programs = dso_local global %struct.anon zeroinitializer, section ".maps", align 8
			if bytes.HasPrefix(bytes.TrimSpace(line), []byte("@")) && bytes.Contains(line, []byte(" global ")) {
				// Extract global name
				parts := bytes.Fields(line)
				if len(parts) > 0 {
					globalName := string(parts[0])

					if idx > 0 && seenGlobals[globalName] {
						// This is a duplicate - convert to extern
						// Replace "= dso_local global" with "= external global"
						newLine := bytes.Replace(line, []byte("= dso_local global"), []byte("= external global"), 1)
						newLine = bytes.Replace(newLine, []byte("= global"), []byte("= external global"), 1)

						// Remove initializer and attributes after global type
						// Find the type (between "global" and the initializer/attributes)
						globalIdx := bytes.Index(newLine, []byte("= external global"))
						if globalIdx != -1 {
							afterGlobal := newLine[globalIdx+17:] // Skip "= external global"
							// Find the end of the type (before zeroinitializer, section, align, etc.)
							typeEnd := bytes.Index(afterGlobal, []byte(" zeroinitializer"))
							if typeEnd == -1 {
								typeEnd = bytes.Index(afterGlobal, []byte(", section"))
							}
							if typeEnd == -1 {
								typeEnd = bytes.Index(afterGlobal, []byte(", align"))
							}
							if typeEnd != -1 {
								newLine = append(newLine[:globalIdx+17+typeEnd], []byte(", align 8")...)
							}
						}

						lines[i] = newLine
						modified = true
						fmt.Printf("    Converting duplicate '%s' to extern in %s\n", globalName, filepath.Base(irPath))
					} else {
						seenGlobals[globalName] = true
					}
				}
			}
		}

		if modified {
			// Write modified IR back
			newData := bytes.Join(lines, []byte("\n"))
			if err := os.WriteFile(irPath, newData, 0644); err != nil {
				return err
			}
		}
	}

	return nil
}

// resizeMapsSection resizes the .maps section to match BTF DATASEC size expectations
func resizeMapsSection(elfPath string) error {
	fmt.Println("Checking .maps section size...")

	// Read the ELF file
	data, err := os.ReadFile(elfPath)
	if err != nil {
		return err
	}

	elfFile, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer elfFile.Close()

	// Find .maps section
	var mapsSection *elf.Section
	var mapsSectionIndex int
	for i, section := range elfFile.Sections {
		if section.Name == ".maps" {
			mapsSection = section
			mapsSectionIndex = i
			break
		}
	}

	if mapsSection == nil {
		return fmt.Errorf(".maps section not found")
	}

	// Parse BTF to find expected .maps size
	// Use bpftool to get BTF info
	cmd := exec.Command("bpftool", "btf", "dump", "file", elfPath, "format", "raw")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to dump BTF: %w", err)
	}

	// Parse output to find DATASEC '.maps' size
	var expectedSize uint64
	lines := bytes.Split(output, []byte("\n"))
	for _, line := range lines {
		if bytes.Contains(line, []byte("DATASEC '.maps'")) {
			// Parse: [484] DATASEC '.maps' size=5840 vlen=24
			parts := bytes.Fields(line)
			for _, part := range parts {
				if bytes.HasPrefix(part, []byte("size=")) {
					sizeStr := string(bytes.TrimPrefix(part, []byte("size=")))
					fmt.Sscanf(sizeStr, "%d", &expectedSize)
					break
				}
			}
			break
		}
	}

	if expectedSize == 0 {
		fmt.Println("  No BTF DATASEC for .maps, keeping current size")
		return nil
	}

	currentSize := mapsSection.Size
	fmt.Printf("  Current .maps size: %d bytes, BTF expects: %d bytes\n", currentSize, expectedSize)

	if currentSize == expectedSize {
		fmt.Println("  .maps section size already matches BTF")
		return nil
	}

	// Resize the .maps section in the ELF file
	// Update section header sh_size field
	shoff := binary.LittleEndian.Uint64(data[40:48])
	mapsSectionHeaderOffset := shoff + uint64(mapsSectionIndex)*64
	shSizeOffset := mapsSectionHeaderOffset + 32 // sh_size is at offset 32 in section header

	binary.LittleEndian.PutUint64(data[shSizeOffset:shSizeOffset+8], expectedSize)

	fmt.Printf("  Resized .maps section from %d to %d bytes\n", currentSize, expectedSize)

	// Write modified ELF
	return os.WriteFile(elfPath, data, 0644)
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
