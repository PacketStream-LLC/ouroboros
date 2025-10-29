package ouroboros

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
)

// LoadedProgram represents a program that has been loaded into the kernel.
type LoadedProgram struct {
	Name       string
	ID         int
	Program    *ebpf.Program
	Collection *ebpf.Collection
}

// LoadOptions contains options for loading eBPF programs.
type LoadOptions struct {
	// PinPath is the directory where programs and maps should be pinned
	PinPath string
	// ReplaceMaps allows replacing existing pinned maps
	ReplaceMaps bool
}

// LoadProgram loads a single eBPF program into the kernel.
// It loads the compiled object file, pins it to the BPF filesystem,
// and returns a handle to the loaded program.
func (o *Ouroboros) LoadProgram(progName string, opts *LoadOptions) (*LoadedProgram, error) {
	if opts == nil {
		opts = &LoadOptions{
			PinPath: o.GetBpfBaseDir(),
		}
	}

	prog := o.GetProgram(progName)
	if prog == nil {
		return nil, fmt.Errorf("program %s not found in config", progName)
	}

	// Check if object file exists
	objPath := o.GetProgramObjectPath(progName)
	if !o.IsProgramBuilt(progName) {
		return nil, fmt.Errorf("program %s not built (missing %s)", progName, objPath)
	}

	// Load the collection
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load collection spec: %w", err)
	}

	// Load collection with pin options
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: opts.PinPath,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load collection: %w", err)
	}

	// Get the first program from the collection (assuming one program per object)
	var loadedProg *ebpf.Program
	for _, p := range coll.Programs {
		loadedProg = p
		break
	}

	if loadedProg == nil {
		coll.Close()
		return nil, fmt.Errorf("no programs found in %s", objPath)
	}

	return &LoadedProgram{
		Name:       progName,
		ID:         prog.ID,
		Program:    loadedProg,
		Collection: coll,
	}, nil
}

// UnloadProgram unloads a program from the kernel and closes its resources.
func (o *Ouroboros) UnloadProgram(loaded *LoadedProgram) error {
	if loaded == nil {
		return fmt.Errorf("nil loaded program")
	}

	if loaded.Collection != nil {
		loaded.Collection.Close()
	}

	if loaded.Program != nil {
		return loaded.Program.Close()
	}

	return nil
}

// PinProgram pins a loaded program to the BPF filesystem.
// This allows the program to persist after the loading process exits.
func (o *Ouroboros) PinProgram(loaded *LoadedProgram) error {
	if loaded == nil || loaded.Program == nil {
		return fmt.Errorf("invalid loaded program")
	}

	pinPath := filepath.Join(o.GetBpfBaseDir(), loaded.Name)
	return loaded.Program.Pin(pinPath)
}

// UnpinProgram unpins a program from the BPF filesystem.
func (o *Ouroboros) UnpinProgram(progName string) error {
	pinPath := filepath.Join(o.GetBpfBaseDir(), progName)
	prog, err := ebpf.LoadPinnedProgram(pinPath, nil)
	if err != nil {
		return err
	}
	return prog.Close()
}

// IsProgramLoaded checks if a program is currently loaded (pinned) in the kernel.
func (o *Ouroboros) IsProgramLoaded(progName string) bool {
	pinPath := filepath.Join(o.GetBpfBaseDir(), progName)
	prog, err := ebpf.LoadPinnedProgram(pinPath, nil)
	if err != nil {
		return false
	}
	prog.Close()
	return true
}

// GetLoadedProgram retrieves a handle to a loaded (pinned) program.
func (o *Ouroboros) GetLoadedProgram(progName string) (*ebpf.Program, error) {
	pinPath := filepath.Join(o.GetBpfBaseDir(), progName)
	return ebpf.LoadPinnedProgram(pinPath, nil)
}

// LoadProgramMap loads or creates the program array map used for tail calls.
func (o *Ouroboros) LoadProgramMap() (*ebpf.Map, error) {
	mapName := o.GetProgramMap()
	mapPath := filepath.Join(o.GetBpfBaseDir(), mapName)

	// Try to load existing map
	progMap, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err == nil {
		return progMap, nil
	}

	// Create new program array map
	maxPrograms := uint32(len(o.ListPrograms()) + 10) // Add some headroom
	progMap, err = ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.ProgramArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: maxPrograms,
		Name:       mapName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create program map: %w", err)
	}

	// Pin the map
	if err := progMap.Pin(mapPath); err != nil {
		progMap.Close()
		return nil, fmt.Errorf("failed to pin program map: %w", err)
	}

	return progMap, nil
}

// UpdateProgramMap updates the program array map with a loaded program.
// This is used for tail call support.
func (o *Ouroboros) UpdateProgramMap(progMap *ebpf.Map, loaded *LoadedProgram) error {
	if progMap == nil || loaded == nil || loaded.Program == nil {
		return fmt.Errorf("invalid program map or loaded program")
	}

	key := uint32(loaded.ID)
	value := uint32(loaded.Program.FD())

	return progMap.Update(key, value, ebpf.UpdateAny)
}

// LoadAllPrograms loads all programs in the project into the kernel.
// Returns a map of program names to loaded programs or errors.
func (o *Ouroboros) LoadAllPrograms(opts *LoadOptions) (map[string]*LoadedProgram, map[string]error) {
	programs := o.ListPrograms()
	loaded := make(map[string]*LoadedProgram)
	errors := make(map[string]error)

	// Load program map first
	progMap, err := o.LoadProgramMap()
	if err != nil {
		// Store error for all programs
		for _, p := range programs {
			errors[p.Name] = fmt.Errorf("failed to load program map: %w", err)
		}
		return loaded, errors
	}
	defer progMap.Close()

	// Load each program
	for _, prog := range programs {
		loadedProg, err := o.LoadProgram(prog.Name, opts)
		if err != nil {
			errors[prog.Name] = err
			continue
		}

		// Update program map for tail calls
		if err := o.UpdateProgramMap(progMap, loadedProg); err != nil {
			errors[prog.Name] = fmt.Errorf("failed to update program map: %w", err)
			o.UnloadProgram(loadedProg)
			continue
		}

		loaded[prog.Name] = loadedProg
	}

	return loaded, errors
}

// UnloadAllPrograms unloads all loaded programs.
func (o *Ouroboros) UnloadAllPrograms() map[string]error {
	programs := o.ListPrograms()
	errors := make(map[string]error)

	for _, prog := range programs {
		if o.IsProgramLoaded(prog.Name) {
			if err := o.UnpinProgram(prog.Name); err != nil {
				errors[prog.Name] = err
			}
		}
	}

	return errors
}
