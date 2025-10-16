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

		progmapSpec := &ebpf.MapSpec{
			Name:       config.ProgramMap,
			Type:       ebpf.ProgramArray,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 65535,
			Pinning:    ebpf.PinByName,
		}

		progmap, err := ebpf.NewMapWithOptions(progmapSpec, bpfMapOptions)

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

			coll, err := ebpf.NewCollectionWithOptions(collSpec, ebpf.CollectionOptions{
				Maps: bpfMapOptions,
			})
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			defer coll.Close()

			xdpProg := coll.Programs[progName]
			if xdpProg == nil {
				if len(coll.Programs) == 1 {
					// fallback mode
					// get first program as xdpProg
					progNameAuto := progName
					for key, prog := range coll.Programs {
						progNameAuto = key
						xdpProg = prog
						break
					}

					fmt.Printf("No xdp program named %s in %s. falling back to %s\n", progName, objFile, progNameAuto)
				} else {
					fmt.Printf("program %s not found in %s\n", progName, objFile)
					os.Exit(1)
				}
			}

			if err := xdpProg.Pin(filepath.Join(bpfBaseDir, progName)); err != nil {
				fmt.Println("error while pinning program", err)
				os.Exit(1)
			}

			if err := progmap.Put(uint32(progID), uint32(xdpProg.FD())); err != nil {
				fmt.Println("error while updating progmap", err)
				os.Exit(1)
			}
		}

		fmt.Println("Load complete.")
	},
}

func init() {
	RootCmd.AddCommand(loadCmd)
}
