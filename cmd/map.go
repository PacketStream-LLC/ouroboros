package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/spf13/cobra"
)

var verbose bool

var mapCmd = &cobra.Command{
	Use:   "map",
	Short: "Commands for eBPF maps",
	Long:  `Commands for inspecting and managing eBPF maps.`,
}

var mapListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all eBPF maps discovered in compiled programs",
	Long: `Analyzes compiled eBPF programs and lists all maps with their specifications.
This includes map type, key size, value size, and max entries.
Matches bpftool map list output format.`,
	Run: func(cmd *cobra.Command, args []string) {
		config, err := ReadConfig()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Check if target directory exists
		if _, err := os.Stat("target"); os.IsNotExist(err) {
			fmt.Println("Error: target directory not found. Run 'ouroboros build' first.")
			os.Exit(1)
		}

		allMaps := make(map[string]*MapInfo)

		// Discover maps from all programs
		for _, prog := range config.Programs {
			progName := prog.Name
			objFile := filepath.Join("target", fmt.Sprintf("%s.o", progName))

			if _, err := os.Stat(objFile); os.IsNotExist(err) {
				if verbose {
					fmt.Printf("Warning: %s not found, skipping %s\n", objFile, progName)
				}
				continue
			}

			collSpec, err := ebpf.LoadCollectionSpec(objFile)
			if err != nil {
				if verbose {
					fmt.Printf("Warning: failed to load %s: %v\n", objFile, err)
				}
				continue
			}

			// Extract maps from this program
			for mapName, mapSpec := range collSpec.Maps {
				if existing, ok := allMaps[mapName]; ok {
					// Map already exists, add this program to the list
					existing.Programs = append(existing.Programs, progName)
				} else {
					// New map discovered
					allMaps[mapName] = &MapInfo{
						Name:       mapName,
						Type:       mapSpec.Type,
						KeySize:    mapSpec.KeySize,
						ValueSize:  mapSpec.ValueSize,
						MaxEntries: mapSpec.MaxEntries,
						Programs:   []string{progName},
					}
				}
			}
		}

		if len(allMaps) == 0 {
			fmt.Println("No maps found in compiled programs.")
			return
		}

		// Try to load pinned maps to get their kernel IDs
		for name, mapInfo := range allMaps {
			pinPath := filepath.Join(config.GetBpfBaseDir(), name)
			if m, err := ebpf.LoadPinnedMap(pinPath, nil); err == nil {
				info, err := m.Info()
				if err == nil {
					id, _ := info.ID()
					mapInfo.ID = uint32(id)
					mapInfo.Pinned = true
				}
				m.Close()
			}
		}

		// Sort maps by name for consistent output
		mapNames := make([]string, 0, len(allMaps))
		for name := range allMaps {
			mapNames = append(mapNames, name)
		}
		sort.Strings(mapNames)

		// Print map information in bpftool style
		for _, name := range mapNames {
			mapInfo := allMaps[name]
			printMapInfoBpftool(mapInfo, verbose)
		}
	},
}

var mapShowCmd = &cobra.Command{
	Use:   "show [name|id]",
	Short: "Show details of a specific map",
	Long: `Show detailed information about a specific eBPF map.
You can specify the map by name or kernel ID.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		config, err := ReadConfig()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Check if target directory exists
		if _, err := os.Stat("target"); os.IsNotExist(err) {
			fmt.Println("Error: target directory not found. Run 'ouroboros build' first.")
			os.Exit(1)
		}

		allMaps := make(map[string]*MapInfo)

		// Discover maps from all programs
		for _, prog := range config.Programs {
			progName := prog.Name
			objFile := filepath.Join("target", fmt.Sprintf("%s%s.o", config.ProgramPrefix, progName))

			if _, err := os.Stat(objFile); os.IsNotExist(err) {
				continue
			}

			collSpec, err := ebpf.LoadCollectionSpec(objFile)
			if err != nil {
				continue
			}

			// Extract maps from this program
			for mapName, mapSpec := range collSpec.Maps {
				if existing, ok := allMaps[mapName]; ok {
					// Map already exists, add this program to the list
					existing.Programs = append(existing.Programs, progName)
				} else {
					// New map discovered
					allMaps[mapName] = &MapInfo{
						Name:       mapName,
						Type:       mapSpec.Type,
						KeySize:    mapSpec.KeySize,
						ValueSize:  mapSpec.ValueSize,
						MaxEntries: mapSpec.MaxEntries,
						Programs:   []string{progName},
					}
				}
			}
		}

		// Try to load pinned maps to get their kernel IDs
		for name, mapInfo := range allMaps {
			pinPath := filepath.Join(config.GetBpfBaseDir(), name)
			if m, err := ebpf.LoadPinnedMap(pinPath, nil); err == nil {
				mapID := m.FD()
				mapInfo.ID = uint32(mapID)
				mapInfo.Pinned = true
				m.Close()
			}
		}

		// If no args, show all maps (same as list but more verbose)
		if len(args) == 0 {
			mapNames := make([]string, 0, len(allMaps))
			for name := range allMaps {
				mapNames = append(mapNames, name)
			}
			sort.Strings(mapNames)

			for _, name := range mapNames {
				mapInfo := allMaps[name]
				printMapInfoDetailed(config, mapInfo)
			}
			return
		}

		// Find specific map by name or ID
		targetName := args[0]
		var targetMap *MapInfo

		// Try to find by name first
		if info, ok := allMaps[targetName]; ok {
			targetMap = info
		} else {
			// Try to parse as ID and find by ID
			var targetID uint32
			if _, err := fmt.Sscanf(targetName, "%d", &targetID); err == nil {
				for _, info := range allMaps {
					if info.Pinned && info.ID == targetID {
						targetMap = info
						break
					}
				}
			}
		}

		if targetMap == nil {
			fmt.Printf("Error: map '%s' not found\n", targetName)
			os.Exit(1)
		}

		printMapInfoDetailed(config, targetMap)
	},
}

type MapInfo struct {
	Name       string
	Type       ebpf.MapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Programs   []string
	ID         uint32
	Pinned     bool
}

func printMapInfoBpftool(info *MapInfo, verbose bool) {
	// Format matching bpftool map list output:
	// Line 1: <id>: <type>  name <name>  flags 0x0
	// Line 2:     key <size>B  value <size>B  max_entries <count>  memlock <size>B

	// First line: ID, type, name, flags
	if info.Pinned && info.ID > 0 {
		// Map is loaded in kernel, show with ID
		fmt.Printf("%d: %s  name %s  flags 0x0\n",
			info.ID,
			mapTypeToLowerString(info.Type),
			info.Name)
	} else {
		// Map not loaded, show without ID
		fmt.Printf("%s  name %s  flags 0x0\n",
			mapTypeToLowerString(info.Type),
			info.Name)
	}

	// Second line: key, value, max_entries, memlock (with 4-space indentation)
	memlock := calculateMemlock(info)
	fmt.Printf("    key %dB  value %dB  max_entries %d  memlock %dB\n",
		info.KeySize,
		info.ValueSize,
		info.MaxEntries,
		memlock)

	// Additional lines for program info if verbose
	if verbose && len(info.Programs) > 0 {
		fmt.Printf("    pids %s\n", strings.Join(info.Programs, ","))
	}
}

func printMapInfoDetailed(config *OuroborosConfig, info *MapInfo) {
	if info.Pinned && info.ID > 0 {
		fmt.Printf("%d: %s  name %s  flags 0x0\n",
			info.ID,
			mapTypeToLowerString(info.Type),
			info.Name)
	} else {
		fmt.Printf("%s  name %s  flags 0x0\n",
			mapTypeToLowerString(info.Type),
			info.Name)
	}

	fmt.Printf("\tkey %dB  value %dB  max_entries %d\n",
		info.KeySize,
		info.ValueSize,
		info.MaxEntries)

	if info.Pinned {
		pinPath := filepath.Join(config.GetBpfBaseDir(), info.Name)
		fmt.Printf("\tpinned %s\n", pinPath)
	}

	if len(info.Programs) > 0 {
		fmt.Printf("\tprograms: %s\n", strings.Join(info.Programs, ", "))
	}

	if len(info.Programs) > 1 || strings.HasPrefix(info.Name, "shared_") {
		fmt.Printf("\tshared: yes\n")
	}

	fmt.Println()
}

func calculateMemlock(info *MapInfo) uint64 {
	// Estimate memlock size based on map type and parameters
	// This is an approximation of kernel memory locked for the map

	var memlock uint64

	// Base overhead per map entry (includes internal kernel structures)
	const entryOverhead = 64

	// Calculate based on map type
	switch info.Type {
	case ebpf.RingBuf:
		// Ringbuf uses max_entries as total buffer size
		memlock = uint64(info.MaxEntries)
		// Add page alignment overhead (round up to page size)
		pageSize := uint64(4096)
		memlock = ((memlock + pageSize - 1) / pageSize) * pageSize
		// Add additional overhead for ringbuf metadata
		memlock += 8192

	case ebpf.PerfEventArray:
		// Perf arrays have per-CPU buffers
		memlock = uint64(info.MaxEntries) * uint64(info.ValueSize)
		memlock += entryOverhead * uint64(info.MaxEntries)

	case ebpf.Array, ebpf.PerCPUArray:
		// Arrays pre-allocate all entries
		entrySize := uint64(info.KeySize) + uint64(info.ValueSize) + entryOverhead
		memlock = entrySize * uint64(info.MaxEntries)

	case ebpf.Hash, ebpf.PerCPUHash, ebpf.LRUHash, ebpf.LRUCPUHash:
		// Hash maps have variable occupancy, estimate at full capacity
		entrySize := uint64(info.KeySize) + uint64(info.ValueSize) + entryOverhead
		memlock = entrySize * uint64(info.MaxEntries)
		// Add hash table overhead (bucket array)
		memlock += uint64(info.MaxEntries) * 8

	case ebpf.ProgramArray, ebpf.ArrayOfMaps, ebpf.HashOfMaps:
		// Map-in-map and prog arrays store references
		entrySize := uint64(info.KeySize) + 8 + entryOverhead // 8 bytes for fd/reference
		memlock = entrySize * uint64(info.MaxEntries)

	default:
		// Default calculation for other map types
		entrySize := uint64(info.KeySize) + uint64(info.ValueSize) + entryOverhead
		memlock = entrySize * uint64(info.MaxEntries)
	}

	// Add base map structure overhead
	memlock += 512

	return memlock
}

func mapTypeToLowerString(mapType ebpf.MapType) string {
	s := mapTypeToString(mapType)
	return strings.ToLower(s)
}

func mapTypeToString(mapType ebpf.MapType) string {
	switch mapType {
	case ebpf.Hash:
		return "hash"
	case ebpf.Array:
		return "array"
	case ebpf.ProgramArray:
		return "prog_array"
	case ebpf.PerfEventArray:
		return "perf_event_array"
	case ebpf.PerCPUHash:
		return "percpu_hash"
	case ebpf.PerCPUArray:
		return "percpu_array"
	case ebpf.StackTrace:
		return "stack_trace"
	case ebpf.CGroupArray:
		return "cgroup_array"
	case ebpf.LRUHash:
		return "lru_hash"
	case ebpf.LRUCPUHash:
		return "lru_percpu_hash"
	case ebpf.LPMTrie:
		return "lpm_trie"
	case ebpf.ArrayOfMaps:
		return "array_of_maps"
	case ebpf.HashOfMaps:
		return "hash_of_maps"
	case ebpf.DevMap:
		return "devmap"
	case ebpf.SockMap:
		return "sockmap"
	case ebpf.CPUMap:
		return "cpumap"
	case ebpf.XSKMap:
		return "xskmap"
	case ebpf.RingBuf:
		return "ringbuf"
	case ebpf.InodeStorage:
		return "inode_storage"
	case ebpf.TaskStorage:
		return "task_storage"
	case ebpf.CGroupStorage:
		return "cgroup_storage"
	case ebpf.StructOpsMap:
		return "struct_ops"
	default:
		return fmt.Sprintf("type_%d", mapType)
	}
}

var mapFlowCmd = &cobra.Command{
	Use:   "flow [map-name]",
	Short: "Generate Mermaid diagram showing program dependencies for maps",
	Long: `Generate a Mermaid flowchart diagram showing which programs use which maps.
If a map name is specified, shows only that map's program dependencies.
Otherwise, shows all maps and their program dependencies.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		config, err := ReadConfig()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Check if target directory exists
		if _, err := os.Stat("target"); os.IsNotExist(err) {
			fmt.Println("Error: target directory not found. Run 'ouroboros build' first.")
			os.Exit(1)
		}

		outputFile, _ := cmd.Flags().GetString("output")
		if outputFile == "" {
			outputFile = "map.mermaid"
		}

		// Discover all maps and their programs
		allMaps := make(map[string]*MapInfo)

		for _, prog := range config.Programs {
			progName := prog.Name
			objFile := filepath.Join("target", fmt.Sprintf("%s.o", progName))

			if _, err := os.Stat(objFile); os.IsNotExist(err) {
				continue
			}

			collSpec, err := ebpf.LoadCollectionSpec(objFile)
			if err != nil {
				continue
			}

			// Extract maps from this program
			for mapName, mapSpec := range collSpec.Maps {
				if existing, ok := allMaps[mapName]; ok {
					existing.Programs = append(existing.Programs, progName)
				} else {
					allMaps[mapName] = &MapInfo{
						Name:       mapName,
						Type:       mapSpec.Type,
						KeySize:    mapSpec.KeySize,
						ValueSize:  mapSpec.ValueSize,
						MaxEntries: mapSpec.MaxEntries,
						Programs:   []string{progName},
					}
				}
			}
		}

		if len(allMaps) == 0 {
			fmt.Println("No maps found in compiled programs.")
			os.Exit(1)
		}

		// Filter to specific map if requested
		var targetMaps map[string]*MapInfo
		if len(args) > 0 {
			mapName := args[0]
			if info, ok := allMaps[mapName]; ok {
				targetMaps = map[string]*MapInfo{mapName: info}
			} else {
				fmt.Printf("Error: map '%s' not found\n", mapName)
				os.Exit(1)
			}
		} else {
			targetMaps = allMaps
		}

		// Generate Mermaid diagram
		mermaid := generateMapFlowMermaid(targetMaps)

		// Write to file
		if err := os.WriteFile(outputFile, []byte(mermaid), 0644); err != nil {
			fmt.Printf("Error: failed to write to %s: %v\n", outputFile, err)
			os.Exit(1)
		}

		fmt.Printf("Generated map dependency diagram: %s\n", outputFile)
	},
}

func generateMapFlowMermaid(maps map[string]*MapInfo) string {
	var sb strings.Builder

	sb.WriteString("graph TD\n")
	sb.WriteString("  %% Map Dependencies\n\n")

	// Sort map names for consistent output
	mapNames := make([]string, 0, len(maps))
	for name := range maps {
		mapNames = append(mapNames, name)
	}
	sort.Strings(mapNames)

	// Generate nodes and edges
	for _, mapName := range mapNames {
		mapInfo := maps[mapName]

		// Create map node with type info
		mapNodeID := fmt.Sprintf("map_%s", sanitizeMermaidID(mapName))
		sb.WriteString(fmt.Sprintf("  %s[\"%s\n(%s)\"]\n",
			mapNodeID,
			mapName,
			mapTypeToString(mapInfo.Type)))

		// Style map node
		sb.WriteString(fmt.Sprintf("  style %s fill:#f9f,stroke:#333,stroke-width:2px\n", mapNodeID))

		// Create edges from programs to map
		for _, progName := range mapInfo.Programs {
			progNodeID := fmt.Sprintf("prog_%s", sanitizeMermaidID(progName))
			sb.WriteString(fmt.Sprintf("  %s[\"%s\"] --> %s\n",
				progNodeID,
				progName,
				mapNodeID))
		}

		sb.WriteString("\n")
	}

	return sb.String()
}

func sanitizeMermaidID(s string) string {
	// Replace characters that are problematic in Mermaid IDs
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, ".", "_")
	s = strings.ReplaceAll(s, " ", "_")
	return s
}

func init() {
	RootCmd.AddCommand(mapCmd)
	mapCmd.AddCommand(mapListCmd)
	mapCmd.AddCommand(mapShowCmd)
	mapCmd.AddCommand(mapFlowCmd)

	mapListCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show program information (like bpftool pids)")
	mapFlowCmd.Flags().StringP("output", "o", "", "Output file path (default: map.mermaid)")
}
