package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/spf13/cobra"
)

var verbose bool
var mapTypeFilter string

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

		// Filter by type if specified
		var filteredMaps map[string]*MapInfo
		if mapTypeFilter != "" {
			filterType := parseMapType(mapTypeFilter)
			if filterType == ebpf.UnspecifiedMap {
				fmt.Printf("Error: unknown map type '%s'\n", mapTypeFilter)
				fmt.Println("Valid types: hash, array, prog_array, perf_event_array, percpu_hash,")
				fmt.Println("             percpu_array, stack_trace, cgroup_array, lru_hash,")
				fmt.Println("             lru_percpu_hash, lpm_trie, array_of_maps, hash_of_maps,")
				fmt.Println("             devmap, sockmap, cpumap, xskmap, ringbuf, etc.")
				os.Exit(1)
			}
			filteredMaps = make(map[string]*MapInfo)
			for name, info := range allMaps {
				if info.Type == filterType {
					filteredMaps[name] = info
				}
			}
		} else {
			filteredMaps = allMaps
		}

		if len(filteredMaps) == 0 {
			if mapTypeFilter != "" {
				fmt.Printf("No maps of type '%s' found.\n", mapTypeFilter)
			} else {
				fmt.Println("No maps found in compiled programs.")
			}
			return
		}

		// Sort maps by name for consistent output
		mapNames := make([]string, 0, len(filteredMaps))
		for name := range filteredMaps {
			mapNames = append(mapNames, name)
		}
		sort.Strings(mapNames)

		// Print map information in bpftool style
		for _, name := range mapNames {
			mapInfo := filteredMaps[name]
			printMapInfoBpftool(mapInfo, verbose)
		}
	},
}

var mapShowCmd = &cobra.Command{
	Use:   "show <name|id>",
	Short: "Show details of a specific map",
	Long: `Show detailed information about a specific eBPF map.
You can specify the map by name or kernel ID.`,
	Args: cobra.ExactArgs(1),
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

func parseMapType(typeStr string) ebpf.MapType {
	typeStr = strings.ToLower(typeStr)
	switch typeStr {
	case "hash":
		return ebpf.Hash
	case "array":
		return ebpf.Array
	case "prog_array", "program_array":
		return ebpf.ProgramArray
	case "perf_event_array":
		return ebpf.PerfEventArray
	case "percpu_hash":
		return ebpf.PerCPUHash
	case "percpu_array":
		return ebpf.PerCPUArray
	case "stack_trace":
		return ebpf.StackTrace
	case "cgroup_array":
		return ebpf.CGroupArray
	case "lru_hash":
		return ebpf.LRUHash
	case "lru_percpu_hash":
		return ebpf.LRUCPUHash
	case "lpm_trie":
		return ebpf.LPMTrie
	case "array_of_maps":
		return ebpf.ArrayOfMaps
	case "hash_of_maps":
		return ebpf.HashOfMaps
	case "devmap", "devmap_hash":
		return ebpf.DevMap
	case "sockmap":
		return ebpf.SockMap
	case "cpumap":
		return ebpf.CPUMap
	case "xskmap":
		return ebpf.XSKMap
	case "ringbuf":
		return ebpf.RingBuf
	case "inode_storage":
		return ebpf.InodeStorage
	case "task_storage":
		return ebpf.TaskStorage
	case "cgroup_storage":
		return ebpf.CGroupStorage
	case "struct_ops":
		return ebpf.StructOpsMap
	default:
		return ebpf.UnspecifiedMap
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

var mapLogCmd = &cobra.Command{
	Use:   "log MAP_NAME",
	Short: "Read and print ringbuf events from a map",
	Long: `Continuously reads events from a ringbuf map and prints them to stdout.
The map must be of type ringbuf, otherwise the command will fail.
Press Ctrl-C to stop reading events.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		mapName := args[0]

		config, err := ReadConfig()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		// Resolve map path
		pinPath := filepath.Join(config.GetBpfBaseDir(), mapName)

		// Check if map exists
		if _, err := os.Stat(pinPath); err != nil {
			fmt.Printf("Error: map '%s' not found at %s\n", mapName, pinPath)
			os.Exit(1)
		}

		// Load the pinned map
		m, err := ebpf.LoadPinnedMap(pinPath, nil)
		if err != nil {
			fmt.Printf("Error: failed to load map '%s': %v\n", mapName, err)
			os.Exit(1)
		}
		defer m.Close()

		// Verify it's a ringbuf map
		info, err := m.Info()
		if err != nil {
			fmt.Printf("Error: failed to get map info: %v\n", err)
			os.Exit(1)
		}

		if info.Type != ebpf.RingBuf {
			fmt.Printf("Error: map '%s' is not a ringbuf (type: %s)\n", mapName, info.Type)
			os.Exit(1)
		}

		// Create ringbuf reader
		rd, err := ringbuf.NewReader(m)
		if err != nil {
			fmt.Printf("Error: failed to create ringbuf reader: %v\n", err)
			os.Exit(1)
		}
		defer rd.Close()

		// Setup signal handling for graceful shutdown
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

		// Channel to signal the reader goroutine to stop
		done := make(chan struct{})

		// Read events in a goroutine
		go func() {
			for {
				select {
				case <-done:
					return
				default:
					record, err := rd.Read()
					if err != nil {
						if errors.Is(err, ringbuf.ErrClosed) {
							return
						}
						// Only print error if we're not shutting down
						select {
						case <-done:
							return
						default:
							fmt.Fprintf(os.Stderr, "Error reading from ringbuf: %v\n", err)
						}
						continue
					}

					// Print the raw data directly to stdout
					os.Stdout.Write(record.RawSample)
				}
			}
		}()

		// Wait for interrupt signal
		<-sig
		fmt.Fprintln(os.Stderr, "\nStopping...")
		close(done)
	},
}

// resolveMapPath resolves a map name to its pinned path
func resolveMapPath(mapName string) (string, error) {
	config, err := ReadConfig()
	if err != nil {
		return "", err
	}
	return filepath.Join(config.GetBpfBaseDir(), mapName), nil
}

// createPassthroughCmd creates a pass-through command for a specific bpftool subcommand
func createPassthroughCmd(subcommand string) *cobra.Command {
	return &cobra.Command{
		Use:                subcommand + " MAP_NAME [args...]",
		Short:              fmt.Sprintf("%s map (pass-through to bpftool)", strings.Title(subcommand)),
		Long:               fmt.Sprintf(`Executes 'bpftool map %s' with automatic map name resolution to pinned paths.`, subcommand),
		DisableFlagParsing: true,
		Run: func(cmd *cobra.Command, args []string) {
			// Check if we have arguments
			if len(args) == 0 {
				fmt.Printf("Usage: ouroboros map %s MAP_NAME [args...]\n", subcommand)
				fmt.Printf("Pass-through to: bpftool map %s\n", subcommand)
				os.Exit(1)
			}

			// Build bpftool command arguments
			bpftoolArgs := []string{"map", subcommand}

			// Check if the first argument is a map name (not a flag or id/pinned keyword)
			mapNameOrID := args[0]
			restArgs := args[1:]

			// If it looks like a map name (not starting with - and not numeric ID), resolve it
			if !strings.HasPrefix(mapNameOrID, "-") && !strings.HasPrefix(mapNameOrID, "id") && !strings.HasPrefix(mapNameOrID, "pinned") {
				// Try to resolve as map name
				pinPath, err := resolveMapPath(mapNameOrID)
				if err != nil {
					fmt.Printf("Error: failed to resolve map path: %v\n", err)
					os.Exit(1)
				}

				// Check if the pinned map exists
				if _, err := os.Stat(pinPath); err == nil {
					// Map exists, use pinned path
					bpftoolArgs = append(bpftoolArgs, "pinned", pinPath)
				} else {
					// Map doesn't exist, might be an ID or other identifier, pass through as-is
					bpftoolArgs = append(bpftoolArgs, mapNameOrID)
				}
			} else {
				// Pass through as-is (already has id/pinned prefix or is a flag)
				bpftoolArgs = append(bpftoolArgs, mapNameOrID)
			}

			// Append remaining arguments
			bpftoolArgs = append(bpftoolArgs, restArgs...)

			// Execute bpftool
			bpftoolPath, err := findBpftool()
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}

			// Use os/exec to run bpftool
			execBpftool(bpftoolPath, bpftoolArgs)
		},
	}
}

// findBpftool locates the bpftool binary
func findBpftool() (string, error) {
	// Check common locations
	locations := []string{
		"/usr/sbin/bpftool",
		"/usr/local/sbin/bpftool",
		"/sbin/bpftool",
	}

	for _, loc := range locations {
		if _, err := os.Stat(loc); err == nil {
			return loc, nil
		}
	}

	// Try to find in PATH
	path, err := exec.LookPath("bpftool")
	if err != nil {
		return "", fmt.Errorf("bpftool not found in standard locations or PATH")
	}

	return path, nil
}

// execBpftool executes bpftool with the given arguments
func execBpftool(bpftoolPath string, args []string) {
	cmd := exec.Command(bpftoolPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Printf("Error executing bpftool: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	RootCmd.AddCommand(mapCmd)
	mapCmd.AddCommand(mapListCmd)
	mapCmd.AddCommand(mapShowCmd)
	mapCmd.AddCommand(mapFlowCmd)
	mapCmd.AddCommand(mapLogCmd)

	// Add pass-through commands for bpftool operations
	mapCmd.AddCommand(
		createPassthroughCmd("dump"),
		createPassthroughCmd("update"),
		createPassthroughCmd("lookup"),
		createPassthroughCmd("getnext"),
		createPassthroughCmd("delete"),
		createPassthroughCmd("pin"),
		createPassthroughCmd("event_pipe"),
		createPassthroughCmd("peek"),
		createPassthroughCmd("push"),
		createPassthroughCmd("pop"),
		createPassthroughCmd("enqueue"),
		createPassthroughCmd("dequeue"),
		createPassthroughCmd("freeze"),
	)

	mapListCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show program information (like bpftool pids)")
	mapListCmd.Flags().StringVarP(&mapTypeFilter, "type", "t", "", "Filter maps by type (e.g., hash, array, ringbuf)")
	mapFlowCmd.Flags().StringP("output", "o", "", "Output file path (default: map.mermaid)")
}
