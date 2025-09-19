package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/spf13/cobra"
)

var loadCmd = &cobra.Command{
	Use:   "load",
	Short: "Load the compiled eBPF programs into the kernel",
	Run: func(cmd *cobra.Command, args []string) {
		config, err := ReadConfig()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Create and pin shared maps
		for _, sharedMap := range config.SharedMaps {
			mapSpec := &ebpf.MapSpec{
				Name:       sharedMap.Name,
				KeySize:    sharedMap.KeySize,
				ValueSize:  sharedMap.ValueSize,
				MaxEntries: sharedMap.MaxEntries,
			}

			switch sharedMap.Type {
			case "Hash":
				mapSpec.Type = ebpf.Hash
			case "Array":
				mapSpec.Type = ebpf.Array
			case "ProgramArray":
				mapSpec.Type = ebpf.ProgramArray
			case "PerfEventArray":
				mapSpec.Type = ebpf.PerfEventArray
			case "PerCPUHash":
				mapSpec.Type = ebpf.PerCPUHash
			case "PerCPUArray":
				mapSpec.Type = ebpf.PerCPUArray
			case "StackTrace":
				mapSpec.Type = ebpf.StackTrace
			case "CGroupArray":
				mapSpec.Type = ebpf.CGroupArray
			case "LRUHash":
				mapSpec.Type = ebpf.LRUHash
			case "LRUCPUHash":
				mapSpec.Type = ebpf.LRUCPUHash
			case "LPMTrie":
				mapSpec.Type = ebpf.LPMTrie
			case "ArrayOfMaps":
				mapSpec.Type = ebpf.ArrayOfMaps
			case "HashOfMaps":
				mapSpec.Type = ebpf.HashOfMaps
			case "DevMap":
				mapSpec.Type = ebpf.DevMap
			case "SockMap":
				mapSpec.Type = ebpf.SockMap
			case "CPUMap":
				mapSpec.Type = ebpf.CPUMap
			case "XSKMap":
				mapSpec.Type = ebpf.XSKMap
			case "RingBuf":
				mapSpec.Type = ebpf.RingBuf
			case "InodeStorage":
				mapSpec.Type = ebpf.InodeStorage
			case "TaskStorage":
				mapSpec.Type = ebpf.TaskStorage
			case "CGroupStorage":
				mapSpec.Type = ebpf.CGroupStorage
			case "StructOps":
				mapSpec.Type = ebpf.StructOpsMap
			case "PCPUArray":
				mapSpec.Type = ebpf.PerCPUArray
			default:
				fmt.Printf("unsupported map type: %s\n", sharedMap.Type)
				os.Exit(1)
			}

			ebpfMap, err := ebpf.NewMap(mapSpec)
			if err != nil {
				fmt.Printf("failed to create shared map %s: %v\n", sharedMap.Name, err)
				os.Exit(1)
			}
			defer ebpfMap.Close()

			if err := ebpfMap.Pin(filepath.Join(bpfBaseDir, sharedMap.Name)); err != nil {
				fmt.Printf("failed to pin shared map %s: %v\n", sharedMap.Name, err)
				os.Exit(1)
			}
			fmt.Printf("Created and pinned shared map %s\n", sharedMap.Name)
		}

		progmapSpec := &ebpf.MapSpec{
			Name:       config.ProgramMap,
			Type:       ebpf.ProgramArray,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 65535,
			Pinning:    ebpf.PinByName,
		}

		progmap, err := ebpf.NewMap(progmapSpec)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		defer progmap.Close()

		if err := progmap.Pin(bpfBaseDir + "/" + config.GetProgramMap()); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		for _, prog := range config.Programs {
			progName := prog.Name
			progID := prog.ID
			objFile := filepath.Join("target", fmt.Sprintf("%s.o", progName))

			collSpec, err := ebpf.LoadCollectionSpec(objFile)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			coll, err := ebpf.NewCollection(collSpec)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			defer coll.Close()

			xdpProg := coll.Programs[progName]
			if xdpProg == nil {
				fmt.Printf("program %s not found in %s\n", progName, objFile)
				os.Exit(1)
			}

			if err := xdpProg.Pin(filepath.Join(bpfBaseDir, progName)); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			if err := progmap.Put(uint32(progID), uint32(xdpProg.FD())); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}

		fmt.Println("Load complete.")
	},
}

func init() {
	RootCmd.AddCommand(loadCmd)
}
