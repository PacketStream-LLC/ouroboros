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
			Fatal("Failed to read config", "error", err)
		}

		Debug("Loading eBPF programs from config",
			"bpf_base_dir", config.GetBpfBaseDir(),
			"program_prefix", config.ProgramPrefix,
			"program_map", config.GetProgramMap(),
			"total_programs", len(config.Programs))

		progmapSpec := &ebpf.MapSpec{
			Name:       config.ProgramMap,
			Type:       ebpf.ProgramArray,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 65535,
			Pinning:    ebpf.PinByName,
		}

		progmap, err := ebpf.NewMapWithOptions(progmapSpec, config.GetMapOptions())

		if err != nil {
			Fatal("Failed to create program array map", "error", err)
		}
		defer progmap.Close()

		progmapPath := filepath.Join(config.GetBpfBaseDir(), config.GetProgramMap())
		if err := progmap.Pin(progmapPath); err != nil {
			Fatal("Failed to pin program array map", "error", err, "path", progmapPath)
		}

		progmapInfo, _ := progmap.Info()
		progmapID, _ := progmapInfo.ID()
		Debug("Created program array map",
			"name", config.GetProgramMap(),
			"id", progmapID,
			"pin_path", progmapPath)

		for i, prog := range config.Programs {
			progName := prog.Name
			progID := prog.ID
			objFile := filepath.Join("target", fmt.Sprintf("%s.o", progName))

			Debug("Loading program",
				"index", i+1,
				"total", len(config.Programs),
				"name", progName,
				"object_file", objFile,
				"program_id", progID)

			collSpec, err := ebpf.LoadCollectionSpec(objFile)
			if err != nil {
				Fatal("Failed to load collection spec", "error", err, "file", objFile)
			}

			Debug("Loaded collection spec",
				"programs_count", len(collSpec.Programs),
				"maps_count", len(collSpec.Maps),
				"entrypoint", prog.Entrypoint)

			coll, err := ebpf.NewCollectionWithOptions(collSpec, ebpf.CollectionOptions{
				Maps: config.GetMapOptions(),
			})
			if err != nil {
				Fatal("Failed to create collection", "error", err, "program", progName)
			}
			defer coll.Close()

			if prog.Entrypoint != "" {
				progName = prog.Entrypoint
			}

			xdpProg := coll.Programs[progName]
			if xdpProg == nil {
				// if collection's program is 1 and only one entrypoint exists
				if len(coll.Programs) == 1 && prog.Entrypoint == "" {
					// fallback mode
					// get first program as xdpProg
					progNameAuto := progName
					for key, prog := range coll.Programs {
						progNameAuto = key
						xdpProg = prog
						break
					}

					Warn("Program not found by name, using fallback",
						"requested", progName,
						"using", progNameAuto,
						"file", objFile)
				} else {
					Fatal("Program not found in collection",
						"program", progName,
						"file", objFile)
				}
			}

			pinPath := filepath.Join(config.GetBpfBaseDir(), config.ProgramPrefix+progName)

			// check if pinPath exists
			if _, err := os.Stat(pinPath); err == nil {
				Debug("Existing program found, unpinning", "path", pinPath)
				prePinnedProgram, err := ebpf.LoadPinnedProgram(pinPath, &ebpf.LoadPinOptions{})
				if err == nil {
					if err := prePinnedProgram.Unpin(); err != nil {
						Fatal("Failed to unpin existing program", "error", err, "path", pinPath)
					}
				}

				// first delete
				if _, err := os.Stat(pinPath); err == nil {
					err = os.Remove(pinPath)
					if err != nil {
						Fatal("Failed to cleanup existing pin path", "error", err, "path", pinPath)
					}
				}
			}

			if err := xdpProg.Pin(pinPath); err != nil {
				Fatal("Failed to pin program", "error", err, "path", pinPath)
			}

			progInfo, _ := xdpProg.Info()
			progKernelID, _ := progInfo.ID()
			Debug("Pinned program",
				"path", pinPath,
				"kernel_id", progKernelID,
				"fd", xdpProg.FD())

			if err := progmap.Put(uint32(progID), uint32(xdpProg.FD())); err != nil {
				Fatal("Failed to update program array", "error", err, "program_id", progID)
			}

			Debug("Added to program array", "index", progID)

			Info("Loaded program", "name", prog.Name, "id", progID)
		}

		Info("Load complete")
	},
}

