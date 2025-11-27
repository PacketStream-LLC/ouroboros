package ouroboros

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/cilium/ebpf"
)

// MapInfo represents an eBPF map with its metadata and relationships.
type MapInfo struct {
	Name       string
	Type       ebpf.MapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	DependsBy  []string // DependsBy that use this map
	ID         uint32   // Kernel ID if loaded
	Pinned     bool     // Whether the map is pinned
}

// ListMapInfos discovers all maps from compiled programs.
// It analyzes the object files to extract map specifications.
func (o *Ouroboros) ListMapInfos() (map[string]*MapInfo, error) {
	allMaps := make(map[string]*MapInfo)

	programs := o.ListPrograms()
	for _, prog := range programs {
		objPath := o.GetProgramObjectPath(prog.Name)

		// Skip if not built
		if !o.IsProgramBuilt(prog.Name) {
			continue
		}

		// Load collection spec
		collSpec, err := ebpf.LoadCollectionSpec(objPath)
		if err != nil {
			// Log but don't fail - just skip this program
			continue
		}

		// Extract maps
		for mapName, mapSpec := range collSpec.Maps {
			if existing, ok := allMaps[mapName]; ok {
				// Map already exists, add this program to the list
				existing.DependsBy = append(existing.DependsBy, prog.Name)
			} else {
				// New map discovered
				allMaps[mapName] = &MapInfo{
					Name:       mapName,
					Type:       mapSpec.Type,
					KeySize:    mapSpec.KeySize,
					ValueSize:  mapSpec.ValueSize,
					MaxEntries: mapSpec.MaxEntries,
					DependsBy:  []string{prog.Name},
				}
			}
		}
	}

	// Try to enrich with pinned map information
	for name, mapInfo := range allMaps {
		pinPath := filepath.Join(o.GetBpfBaseDir(), name)
		if m, err := ebpf.LoadPinnedMap(pinPath, nil); err == nil {
			if info, err := m.Info(); err == nil {
				if id, ok := info.ID(); ok {
					mapInfo.ID = uint32(id)
					mapInfo.Pinned = true
				}
			}
			m.Close()
		}
	}

	return allMaps, nil
}

func (o *Ouroboros) GetMap(mapName string) (*ebpf.Map, error) {
	return ebpf.LoadPinnedMap(filepath.Join(o.GetBpfBaseDir(), mapName), nil)
}

// GetMapInfo returns information about a specific map by name.
func (o *Ouroboros) GetMapInfo(mapName string) (*MapInfo, error) {
	maps, err := o.ListMapInfos()
	if err != nil {
		return nil, err
	}

	mapInfo, ok := maps[mapName]
	if !ok {
		return nil, fmt.Errorf("map %s not found", mapName)
	}

	return mapInfo, nil
}

// GetMapInfosByProgram returns all maps used by a specific program.
func (o *Ouroboros) GetMapInfosByProgram(progName string) (map[string]*MapInfo, error) {
	objPath := o.GetProgramObjectPath(progName)

	if !o.IsProgramBuilt(progName) {
		return nil, fmt.Errorf("program %s not built", progName)
	}

	collSpec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load collection spec: %w", err)
	}

	programMaps := make(map[string]*MapInfo)
	for mapName, mapSpec := range collSpec.Maps {
		programMaps[mapName] = &MapInfo{
			Name:       mapName,
			Type:       mapSpec.Type,
			KeySize:    mapSpec.KeySize,
			ValueSize:  mapSpec.ValueSize,
			MaxEntries: mapSpec.MaxEntries,
			DependsBy:  []string{progName},
		}
	}

	return programMaps, nil
}

// GetProgramsByMap returns all programs that use a specific map.
func (o *Ouroboros) GetProgramsByMap(mapName string) ([]string, error) {
	mapInfo, err := o.GetMapInfo(mapName)
	if err != nil {
		return nil, err
	}

	return mapInfo.DependsBy, nil
}

// LoadPinnedMap loads a pinned map by name and returns the handle.
func (o *Ouroboros) LoadPinnedMap(mapName string) (*ebpf.Map, error) {
	pinPath := filepath.Join(o.GetBpfBaseDir(), mapName)

	if _, err := os.Stat(pinPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("map %s not pinned at %s", mapName, pinPath)
	}

	return ebpf.LoadPinnedMap(pinPath, nil)
}

// IsMapShared returns true if a map is used by multiple programs.
func (o *Ouroboros) IsMapShared(mapName string) (bool, error) {
	programs, err := o.GetProgramsByMap(mapName)
	if err != nil {
		return false, err
	}

	return len(programs) > 1, nil
}

// CalculateMapMemlock estimates the memory locked by a map.
// This is an approximation of kernel memory usage.
func CalculateMapMemlock(mapInfo *MapInfo) uint64 {
	const entryOverhead = 64

	var memlock uint64

	switch mapInfo.Type {
	case ebpf.RingBuf:
		memlock = uint64(mapInfo.MaxEntries)
		pageSize := uint64(4096)
		memlock = ((memlock + pageSize - 1) / pageSize) * pageSize
		memlock += 8192

	case ebpf.PerfEventArray:
		memlock = uint64(mapInfo.MaxEntries) * uint64(mapInfo.ValueSize)
		memlock += entryOverhead * uint64(mapInfo.MaxEntries)

	case ebpf.Array, ebpf.PerCPUArray:
		entrySize := uint64(mapInfo.KeySize) + uint64(mapInfo.ValueSize) + entryOverhead
		memlock = entrySize * uint64(mapInfo.MaxEntries)

	case ebpf.Hash, ebpf.PerCPUHash, ebpf.LRUHash, ebpf.LRUCPUHash:
		entrySize := uint64(mapInfo.KeySize) + uint64(mapInfo.ValueSize) + entryOverhead
		memlock = entrySize * uint64(mapInfo.MaxEntries)
		memlock += uint64(mapInfo.MaxEntries) * 8

	case ebpf.ProgramArray, ebpf.ArrayOfMaps, ebpf.HashOfMaps:
		entrySize := uint64(mapInfo.KeySize) + 8 + entryOverhead
		memlock = entrySize * uint64(mapInfo.MaxEntries)

	default:
		entrySize := uint64(mapInfo.KeySize) + uint64(mapInfo.ValueSize) + entryOverhead
		memlock = entrySize * uint64(mapInfo.MaxEntries)
	}

	memlock += 512
	return memlock
}

// MapAnalysis contains analysis results for maps and their relationships.
type MapAnalysis struct {
	TotalMaps    int
	SharedMaps   []string
	UniqueMaps   []string
	MapsByType   map[ebpf.MapType][]string
	Dependencies map[string][]string // map name -> programs using it
}

// AnalyzeMaps performs comprehensive analysis of all maps.
func (o *Ouroboros) AnalyzeMaps() (*MapAnalysis, error) {
	maps, err := o.ListMapInfos()
	if err != nil {
		return nil, err
	}

	analysis := &MapAnalysis{
		TotalMaps:    len(maps),
		SharedMaps:   []string{},
		UniqueMaps:   []string{},
		MapsByType:   make(map[ebpf.MapType][]string),
		Dependencies: make(map[string][]string),
	}

	for name, mapInfo := range maps {
		// Classify by sharing
		if len(mapInfo.DependsBy) > 1 {
			analysis.SharedMaps = append(analysis.SharedMaps, name)
		} else {
			analysis.UniqueMaps = append(analysis.UniqueMaps, name)
		}

		// Group by type
		analysis.MapsByType[mapInfo.Type] = append(analysis.MapsByType[mapInfo.Type], name)

		// Record dependencies
		analysis.Dependencies[name] = mapInfo.DependsBy
	}

	// Sort for consistent output
	sort.Strings(analysis.SharedMaps)
	sort.Strings(analysis.UniqueMaps)
	for _, maps := range analysis.MapsByType {
		sort.Strings(maps)
	}

	return analysis, nil
}

// MapTypeToString converts a map type to its string representation.
func MapTypeToString(mapType ebpf.MapType) string {
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
