package utils

import (
	"strings"

	"github.com/cilium/ebpf"
)

// ParseMapType converts a string map type name to ebpf.MapType
func ParseMapType(typeStr string) ebpf.MapType {
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
