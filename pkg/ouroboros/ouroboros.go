// Package ouroboros provides a Go SDK for managing multiple eBPF programs.
//
// This package allows you to programmatically interact with Ouroboros projects,
// manage eBPF programs, and perform operations like building, loading, and attaching
// programs without using the CLI.
//
// Example usage:
//
//	import "github.com/PacketStream-LLC/ouroboros/pkg/ouroboros"
//
//	// Load an existing project
//	o, err := ouroboros.New()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Add a new program
//	prog := ouroboros.Program{
//	    Name: "myprogram",
//	}
//	if err := o.AddProgram(prog); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Save configuration
//	if err := o.SaveConfig(); err != nil {
//	    log.Fatal(err)
//	}
package ouroboros

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/PacketStream-LLC/ouroboros/internal/config"
	"github.com/PacketStream-LLC/ouroboros/pkg/constants"
	"github.com/cilium/ebpf"
)

// Ouroboros represents the main SDK instance for managing eBPF programs.
// It encapsulates the project configuration and provides methods for
// program management, building, loading, and other operations.
type Ouroboros struct {
	config *config.OuroborosConfig
}

// Program represents an eBPF program in the project.
type Program struct {
	Name       string           `json:"name"`
	ID         int              `json:"id"`
	IsMain     bool             `json:"is_main,omitempty"`
	Metadata   *ProgramMetadata `json:"metadata,omitempty"`
	Entrypoint string           `json:"entrypoint,omitempty"`
}

// ProgramMetadata contains additional program metadata.
type ProgramMetadata struct {
	HiddenOnFlow bool `json:"hidden_on_flow,omitempty"`
}

// Config represents the Ouroboros project configuration.
type Config struct {
	Programs      []Program `json:"programs"`
	CompileArgs   []string  `json:"compile_args"`
	ProgramMap    string    `json:"program_map,omitempty"`
	ProgramPrefix string    `json:"program_prefix,omitempty"`
	BpfBaseDir    string    `json:"bpf_base_dir,omitempty"`
}

// New creates a new Ouroboros SDK instance by loading the configuration
// from the current directory. Returns an error if the configuration file
// doesn't exist or is invalid.
func New() (*Ouroboros, error) {
	cfg, err := config.ReadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	return &Ouroboros{
		config: cfg,
	}, nil
}

// NewWithConfig creates a new Ouroboros SDK instance with the provided configuration.
// This is useful for creating projects programmatically or for testing.
func NewWithConfig(cfg *Config) *Ouroboros {
	return &Ouroboros{
		config: toInternalConfig(cfg),
	}
}

// Config returns a copy of the current configuration.
func (o *Ouroboros) Config() *Config {
	return fromInternalConfig(o.config)
}

// SaveConfig writes the current configuration to disk.
func (o *Ouroboros) SaveConfig() error {
	return config.WriteConfig(o.config)
}

// ReloadConfig reloads the configuration from disk.
func (o *Ouroboros) ReloadConfig() error {
	cfg, err := config.ReadConfig()
	if err != nil {
		return fmt.Errorf("failed to reload config: %w", err)
	}
	o.config = cfg
	return nil
}

// GetProjectRoot returns the project root directory (where ouroboros.json is located).
func (o *Ouroboros) GetProjectRoot() (string, error) {
	return config.FindProjectRoot()
}

// GetSrcDir returns the absolute path to the src directory.
func (o *Ouroboros) GetSrcDir() (string, error) {
	root, err := o.GetProjectRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, constants.SrcDir), nil
}

// GetTargetDir returns the absolute path to the target directory.
func (o *Ouroboros) GetTargetDir() (string, error) {
	root, err := o.GetProjectRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, constants.TargetDir), nil
}

// GetOuroborosGlobalDir returns the absolute path to the _ouroboros directory.
func (o *Ouroboros) GetOuroborosGlobalDir() (string, error) {
	root, err := o.GetProjectRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, constants.OuroborosGlobalDir), nil
}

// GetProgram finds a program by name. Returns nil if not found.
func (o *Ouroboros) GetProgram(name string) *Program {
	for i := range o.config.Programs {
		if o.config.Programs[i].Name == name {
			return fromInternalProgram(&o.config.Programs[i])
		}
	}
	return nil
}

// GetProgramByID finds a program by ID. Returns nil if not found.
func (o *Ouroboros) GetProgramByID(id int) *Program {
	for i := range o.config.Programs {
		if o.config.Programs[i].ID == id {
			return fromInternalProgram(&o.config.Programs[i])
		}
	}
	return nil
}

// AddProgram adds a new program to the configuration.
// If the program ID is 0, it will be automatically assigned.
// Returns an error if a program with the same name already exists.
func (o *Ouroboros) AddProgram(prog Program) error {
	// Check if program already exists
	if o.GetProgram(prog.Name) != nil {
		return fmt.Errorf("program %s already exists", prog.Name)
	}

	// Assign next available ID if not set
	if prog.ID == 0 {
		prog.ID = o.GetNextProgramID()
	}

	o.config.Programs = append(o.config.Programs, *toInternalProgram(&prog))
	return nil
}

// RemoveProgram removes a program from the configuration by name.
func (o *Ouroboros) RemoveProgram(name string) error {
	for i, p := range o.config.Programs {
		if p.Name == name {
			o.config.Programs = append(o.config.Programs[:i], o.config.Programs[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("program %s not found", name)
}

// GetNextProgramID returns the next available program ID.
func (o *Ouroboros) GetNextProgramID() int {
	maxID := 0
	for _, p := range o.config.Programs {
		if p.ID > maxID {
			maxID = p.ID
		}
	}
	return maxID + 1
}

// GetMainProgram returns the main program, or nil if no main program is set.
func (o *Ouroboros) GetMainProgram() *Program {
	p := o.config.GetMainProgram()
	if p == nil {
		return nil
	}
	return fromInternalProgram(p)
}

// ListPrograms returns all programs in the configuration.
func (o *Ouroboros) ListPrograms() []Program {
	programs := make([]Program, len(o.config.Programs))
	for i := range o.config.Programs {
		programs[i] = *fromInternalProgram(&o.config.Programs[i])
	}
	return programs
}

// GetProgramMap returns the configured program map name.
func (o *Ouroboros) GetProgramMap() string {
	return o.config.GetProgramMap()
}

// GetBpfBaseDir returns the BPF filesystem base directory.
func (o *Ouroboros) GetBpfBaseDir() string {
	return o.config.GetBpfBaseDir()
}

// GetMapOptions returns eBPF map options with the configured pin path.
func (o *Ouroboros) GetMapOptions() ebpf.MapOptions {
	return o.config.GetMapOptions()
}

// GetCompileArgs returns the compile arguments from configuration.
func (o *Ouroboros) GetCompileArgs() []string {
	return o.config.CompileArgs
}

// SetCompileArgs sets the compile arguments.
func (o *Ouroboros) SetCompileArgs(args []string) {
	o.config.CompileArgs = args
}

// Path Operations

// GetProgramPath returns the filesystem path for a program's source directory.
func (o *Ouroboros) GetProgramPath(progName string) string {
	return filepath.Join(constants.SrcDir, progName)
}

// GetProgramMainFile returns the path to a program's main.c file.
func (o *Ouroboros) GetProgramMainFile(progName string) string {
	return filepath.Join(o.GetProgramPath(progName), constants.EntryPointFile)
}

// GetProgramObjectPath returns the path to a compiled program object file.
func (o *Ouroboros) GetProgramObjectPath(progName string) string {
	return filepath.Join(constants.TargetDir, fmt.Sprintf("%s.o", progName))
}

// GetProgramLLPath returns the path to a program's LLVM IR file.
func (o *Ouroboros) GetProgramLLPath(progName string) string {
	return filepath.Join(constants.TargetDir, fmt.Sprintf("%s.ll", progName))
}

// Directory Operations

// EnsureProgramDirectory creates a program's source directory if it doesn't exist.
func (o *Ouroboros) EnsureProgramDirectory(progName string) error {
	progDir := o.GetProgramPath(progName)
	if err := os.MkdirAll(progDir, 0755); err != nil {
		return fmt.Errorf("failed to create program directory %s: %w", progDir, err)
	}
	return nil
}

// EnsureTargetDirectory creates the target directory if it doesn't exist.
func (o *Ouroboros) EnsureTargetDirectory() error {
	if err := os.MkdirAll(constants.TargetDir, 0755); err != nil {
		return fmt.Errorf("failed to create target directory: %w", err)
	}
	return nil
}

// EnsureGlobalDirectory creates the global ouroboros directory if it doesn't exist.
func (o *Ouroboros) EnsureGlobalDirectory() error {
	if err := os.MkdirAll(constants.OuroborosGlobalDir, 0755); err != nil {
		return fmt.Errorf("failed to create global directory: %w", err)
	}
	return nil
}

// Internal conversion functions

func toInternalConfig(cfg *Config) *config.OuroborosConfig {
	programs := make([]config.Program, len(cfg.Programs))
	for i := range cfg.Programs {
		programs[i] = *toInternalProgram(&cfg.Programs[i])
	}

	return &config.OuroborosConfig{
		Programs:      programs,
		CompileArgs:   cfg.CompileArgs,
		ProgramMap:    cfg.ProgramMap,
		ProgramPrefix: cfg.ProgramPrefix,
		BpfBaseDir:    cfg.BpfBaseDir,
	}
}

func fromInternalConfig(cfg *config.OuroborosConfig) *Config {
	programs := make([]Program, len(cfg.Programs))
	for i := range cfg.Programs {
		programs[i] = *fromInternalProgram(&cfg.Programs[i])
	}

	return &Config{
		Programs:      programs,
		CompileArgs:   cfg.CompileArgs,
		ProgramMap:    cfg.ProgramMap,
		ProgramPrefix: cfg.ProgramPrefix,
		BpfBaseDir:    cfg.BpfBaseDir,
	}
}

func toInternalProgram(p *Program) *config.Program {
	var metadata *config.ProgramMetadata
	if p.Metadata != nil {
		metadata = &config.ProgramMetadata{
			HiddenOnFlow: p.Metadata.HiddenOnFlow,
		}
	}

	return &config.Program{
		Name:       p.Name,
		ID:         p.ID,
		IsMain:     p.IsMain,
		Metadata:   metadata,
		Entrypoint: p.Entrypoint,
	}
}

func fromInternalProgram(p *config.Program) *Program {
	var metadata *ProgramMetadata
	if p.Metadata != nil {
		metadata = &ProgramMetadata{
			HiddenOnFlow: p.Metadata.HiddenOnFlow,
		}
	}

	return &Program{
		Name:       p.Name,
		ID:         p.ID,
		IsMain:     p.IsMain,
		Metadata:   metadata,
		Entrypoint: p.Entrypoint,
	}
}
