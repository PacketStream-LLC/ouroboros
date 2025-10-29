package cli

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/PacketStream-LLC/ouroboros/internal/core"
	"github.com/PacketStream-LLC/ouroboros/internal/logger"
	"github.com/PacketStream-LLC/ouroboros/internal/utils"
	sdk "github.com/PacketStream-LLC/ouroboros/pkg/ouroboros"

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
		// Get verbose from root flags
		verbose, _ := cmd.Root().PersistentFlags().GetBool("verbose")

		// Get Ouroboros instance
		o := MustGetOuroboros(cmd)

		// List all maps using SDK
		allMaps, err := o.SDK().ListMaps()
		if err != nil {
			logger.Fatal("Failed to list maps", "error", err)
		}

		if len(allMaps) == 0 {
			logger.Info("No maps found in compiled programs")
			return
		}

		// Filter by type if specified
		var filteredMaps map[string]*sdk.MapInfo
		if mapTypeFilter != "" {
			filterType := utils.ParseMapType(mapTypeFilter)
			if filterType == ebpf.UnspecifiedMap {
				logger.Error("Unknown map type",
					"type", mapTypeFilter,
					"valid_types", "hash, array, prog_array, perf_event_array, percpu_hash, percpu_array, stack_trace, cgroup_array, lru_hash, lru_percpu_hash, lpm_trie, array_of_maps, hash_of_maps, devmap, sockmap, cpumap, xskmap, ringbuf")
				os.Exit(1)
			}
			filteredMaps = make(map[string]*sdk.MapInfo)
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
				logger.Info("No maps of specified type found", "type", mapTypeFilter)
			} else {
				logger.Info("No maps found in compiled programs")
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
		// Get Ouroboros instance
		o := MustGetOuroboros(cmd)

		// List all maps to search
		allMaps, err := o.SDK().ListMaps()
		if err != nil {
			logger.Fatal("Failed to list maps", "error", err)
		}

		// Find specific map by name or ID
		targetName := args[0]
		var targetMap *sdk.MapInfo

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
			logger.Fatal("Map not found", "map", targetName)
		}

		printMapInfoDetailed(o, targetMap)
	},
}

func printMapInfoBpftool(info *sdk.MapInfo, verbose bool) {
	// Format matching bpftool map list output:
	// Line 1: <id>: <type>  name <name>  flags 0x0
	// Line 2:     key <size>B  value <size>B  max_entries <count>  memlock <size>B

	// First line: ID, type, name, flags
	if info.Pinned && info.ID > 0 {
		// Map is loaded in kernel, show with ID
		fmt.Printf("%d: %s  name %s  flags 0x0\n",
			info.ID,
			sdk.MapTypeToString(info.Type),
			info.Name)
	} else {
		// Map not loaded, show without ID
		fmt.Printf("%s  name %s  flags 0x0\n",
			sdk.MapTypeToString(info.Type),
			info.Name)
	}

	// Second line: key, value, max_entries, memlock (with 4-space indentation)
	memlock := sdk.CalculateMapMemlock(info)
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

func printMapInfoDetailed(o *core.Ouroboros, info *sdk.MapInfo) {
	if info.Pinned && info.ID > 0 {
		fmt.Printf("%d: %s  name %s  flags 0x0\n",
			info.ID,
			sdk.MapTypeToString(info.Type),
			info.Name)
	} else {
		fmt.Printf("%s  name %s  flags 0x0\n",
			sdk.MapTypeToString(info.Type),
			info.Name)
	}

	fmt.Printf("\tkey %dB  value %dB  max_entries %d\n",
		info.KeySize,
		info.ValueSize,
		info.MaxEntries)

	if info.Pinned {
		pinPath := filepath.Join(o.SDK().GetBpfBaseDir(), info.Name)
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

var mapFlowCmd = &cobra.Command{
	Use:   "flow [map-name]",
	Short: "Generate Mermaid diagram showing program dependencies for maps",
	Long: `Generate a Mermaid flowchart diagram showing which programs use which maps.
If a map name is specified, shows only that map's program dependencies.
Otherwise, shows all maps and their program dependencies.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Resolve output file path relative to CWD
		outputFile, _ := cmd.Flags().GetString("output")
		if outputFile == "" {
			outputFile = "map.mermaid"
		}
		outputFilePath, err := utils.ResolveCwdPath(outputFile)
		if err != nil {
			logger.Fatal("Failed to resolve output file path", "error", err)
		}

		// Execute in project root context
		if err := utils.WithProjectRoot(func() error {
			// Get Ouroboros instance
			o := MustGetOuroboros(cmd)

			// Discover all maps using SDK
			allMaps, err := o.SDK().ListMaps()
			if err != nil {
				return fmt.Errorf("failed to list maps: %w", err)
			}

			if len(allMaps) == 0 {
				return fmt.Errorf("no maps found in compiled programs")
			}
			return generateMapFlowDiagram(args, allMaps, outputFilePath)
		}); err != nil {
			logger.Fatal("Failed to generate map flow diagram", "error", err)
		}
	},
}

func generateMapFlowDiagram(args []string, allMaps map[string]*sdk.MapInfo, outputFilePath string) error {
	// Filter to specific map if requested
	var targetMaps map[string]*sdk.MapInfo
	if len(args) > 0 {
		mapName := args[0]
		if info, ok := allMaps[mapName]; ok {
			targetMaps = map[string]*sdk.MapInfo{mapName: info}
		} else {
			return fmt.Errorf("map '%s' not found", mapName)
		}
	} else {
		targetMaps = allMaps
	}

	// Generate Mermaid diagram
	mermaid := generateMapFlowMermaid(targetMaps)

	// Write to file
	if err := os.WriteFile(outputFilePath, []byte(mermaid), 0644); err != nil {
		return fmt.Errorf("failed to write to %s: %w", outputFilePath, err)
	}

	fmt.Printf("Generated map dependency diagram: %s\n", outputFilePath)
	return nil
}

func generateMapFlowMermaid(maps map[string]*sdk.MapInfo) string {
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
			sdk.MapTypeToString(mapInfo.Type)))

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

// migrate code from ebpf-caseoh, internal ringbuf piping tool
var mapLogCmd = &cobra.Command{
	Use:   "log MAP_NAME",
	Short: "Read and print ringbuf events from a map",
	Long: `Continuously reads events from a ringbuf map and prints them to stdout.
The map must be of type ringbuf, otherwise the command will fail.
Press Ctrl-C to stop reading events.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		mapName := args[0]
		raw, _ := cmd.Flags().GetBool("raw")

		// Raw mode disables all logging
		if raw {
			logger.SetRawMode(true)
		}

		// Get Ouroboros instance
		o := MustGetOuroboros(cmd)

		// Load the pinned map using SDK
		m, err := o.SDK().LoadPinnedMap(mapName)
		if err != nil {
			logger.Fatal("Failed to load pinned map",
				"map", mapName,
				"error", err)
		}
		defer m.Close()

		// Verify it's a ringbuf map
		info, err := m.Info()
		if err != nil {
			logger.Fatal("Failed to get map info", "error", err)
		}

		if info.Type != ebpf.RingBuf {
			logger.Fatal("Map is not a ringbuf",
				"map", mapName,
				"type", info.Type)
		}

		mapID, _ := info.ID()
		pinPath := filepath.Join(o.SDK().GetBpfBaseDir(), mapName)
		logger.Debug("Reading from ringbuf map",
			"map", mapName,
			"id", mapID,
			"path", pinPath,
			"max_entries", info.MaxEntries)

		// Create ringbuf reader
		rd, err := ringbuf.NewReader(m)
		if err != nil {
			logger.Fatal("Failed to create ringbuf reader", "error", err)
		}
		defer rd.Close()

		// Setup signal handling for graceful shutdown
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

		// Channel to signal the reader goroutine to stop
		done := make(chan struct{})

		// Event counter for verbose mode
		eventCount := uint64(0)

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

					eventCount++

					logger.Debug("Received event",
						"number", eventCount,
						"size", len(record.RawSample))

					// Print the raw data directly to stdout
					os.Stdout.Write(record.RawSample)
				}
			}
		}()

		// Wait for interrupt signal
		<-sig
		logger.Debug("Total events read", "count", eventCount)
		logger.Info("Stopping event reader")
		close(done)
	},
}

// resolveMapPath resolves a map name to its pinned path
func resolveMapPath(mapName string) (string, error) {
	o, err := core.New()
	if err != nil {
		return "", err
	}
	return filepath.Join(o.SDK().GetBpfBaseDir(), mapName), nil
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
			bpftoolPath, err := utils.FindBpftool()
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}

			// Use os/exec to run bpftool
			utils.ExecBpftool(bpftoolPath, bpftoolArgs)
		},
	}
}

func init() {
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

	mapListCmd.Flags().StringVarP(&mapTypeFilter, "type", "t", "", "Filter maps by type (e.g., hash, array, ringbuf)")
	mapFlowCmd.Flags().StringP("output", "o", "", "Output file path (default: map.mermaid)")
	mapLogCmd.Flags().BoolP("raw", "r", false, "Raw mode: disable all logging output (only event data)")
}
