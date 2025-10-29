package core

import (
	"github.com/PacketStream-LLC/ouroboros/internal/config"
	sdk "github.com/PacketStream-LLC/ouroboros/pkg/ouroboros"
	"github.com/cilium/ebpf"
)

// Ouroboros is a wrapper around the public SDK for internal use.
// This allows internal code to continue using the same API while
// the SDK remains available for external users.
type Ouroboros struct {
	sdk *sdk.Ouroboros
}

// New creates a new Ouroboros instance by loading the configuration
func New() (*Ouroboros, error) {
	s, err := sdk.New()
	if err != nil {
		return nil, err
	}

	return &Ouroboros{sdk: s}, nil
}

// NewWithConfig creates a new Ouroboros instance with the provided configuration
func NewWithConfig(cfg *config.OuroborosConfig) *Ouroboros {
	// Convert internal config to SDK config
	sdkConfig := &sdk.Config{
		Programs:      toSDKPrograms(cfg.Programs),
		CompileArgs:   cfg.CompileArgs,
		ProgramMap:    cfg.ProgramMap,
		ProgramPrefix: cfg.ProgramPrefix,
		BpfBaseDir:    cfg.BpfBaseDir,
	}

	return &Ouroboros{
		sdk: sdk.NewWithConfig(sdkConfig),
	}
}

// SDK returns the underlying SDK instance for direct access
func (o *Ouroboros) SDK() *sdk.Ouroboros {
	return o.sdk
}

// Config returns the current configuration in internal format
func (o *Ouroboros) Config() *config.OuroborosConfig {
	cfg := o.sdk.Config()
	return &config.OuroborosConfig{
		Programs:      toInternalPrograms(cfg.Programs),
		CompileArgs:   cfg.CompileArgs,
		ProgramMap:    cfg.ProgramMap,
		ProgramPrefix: cfg.ProgramPrefix,
		BpfBaseDir:    cfg.BpfBaseDir,
	}
}

// SaveConfig writes the current configuration to disk
func (o *Ouroboros) SaveConfig() error {
	return o.sdk.SaveConfig()
}

// ReloadConfig reloads the configuration from disk
func (o *Ouroboros) ReloadConfig() error {
	return o.sdk.ReloadConfig()
}

// GetProjectRoot returns the project root directory (where ouroboros.json is located)
func (o *Ouroboros) GetProjectRoot() (string, error) {
	return o.sdk.GetProjectRoot()
}

// GetSrcDir returns the absolute path to the src directory
func (o *Ouroboros) GetSrcDir() (string, error) {
	return o.sdk.GetSrcDir()
}

// GetTargetDir returns the absolute path to the target directory
func (o *Ouroboros) GetTargetDir() (string, error) {
	return o.sdk.GetTargetDir()
}

// GetOuroborosGlobalDir returns the absolute path to the _ouroboros directory
func (o *Ouroboros) GetOuroborosGlobalDir() (string, error) {
	return o.sdk.GetOuroborosGlobalDir()
}

// GetProgram finds a program by name
func (o *Ouroboros) GetProgram(name string) *config.Program {
	p := o.sdk.GetProgram(name)
	if p == nil {
		return nil
	}
	return toInternalProgram(p)
}

// GetProgramByID finds a program by ID
func (o *Ouroboros) GetProgramByID(id int) *config.Program {
	p := o.sdk.GetProgramByID(id)
	if p == nil {
		return nil
	}
	return toInternalProgram(p)
}

// AddProgram adds a new program to the configuration
func (o *Ouroboros) AddProgram(prog config.Program) error {
	return o.sdk.AddProgram(*toSDKProgram(&prog))
}

// RemoveProgram removes a program from the configuration
func (o *Ouroboros) RemoveProgram(name string) error {
	return o.sdk.RemoveProgram(name)
}

// GetNextProgramID returns the next available program ID
func (o *Ouroboros) GetNextProgramID() int {
	return o.sdk.GetNextProgramID()
}

// GetMainProgram returns the main program
func (o *Ouroboros) GetMainProgram() *config.Program {
	p := o.sdk.GetMainProgram()
	if p == nil {
		return nil
	}
	return toInternalProgram(p)
}

// GetProgramMap returns the configured program map name
func (o *Ouroboros) GetProgramMap() string {
	return o.sdk.GetProgramMap()
}

// GetBpfBaseDir returns the BPF filesystem base directory
func (o *Ouroboros) GetBpfBaseDir() string {
	return o.sdk.GetBpfBaseDir()
}

// GetMapOptions returns eBPF map options with pin path
func (o *Ouroboros) GetMapOptions() ebpf.MapOptions {
	return o.sdk.GetMapOptions()
}

// GetProgramPath returns the filesystem path for a program's source directory
func (o *Ouroboros) GetProgramPath(progName string) string {
	return o.sdk.GetProgramPath(progName)
}

// GetProgramMainFile returns the path to a program's main.c file
func (o *Ouroboros) GetProgramMainFile(progName string) string {
	return o.sdk.GetProgramMainFile(progName)
}

// GetProgramObjectPath returns the path to a compiled program object file
func (o *Ouroboros) GetProgramObjectPath(progName string) string {
	return o.sdk.GetProgramObjectPath(progName)
}

// GetProgramLLPath returns the path to a program's LLVM IR file
func (o *Ouroboros) GetProgramLLPath(progName string) string {
	return o.sdk.GetProgramLLPath(progName)
}

// EnsureProgramDirectory creates a program's source directory if it doesn't exist
func (o *Ouroboros) EnsureProgramDirectory(progName string) error {
	return o.sdk.EnsureProgramDirectory(progName)
}

// EnsureTargetDirectory creates the target directory if it doesn't exist
func (o *Ouroboros) EnsureTargetDirectory() error {
	return o.sdk.EnsureTargetDirectory()
}

// EnsureGlobalDirectory creates the global ouroboros directory if it doesn't exist
func (o *Ouroboros) EnsureGlobalDirectory() error {
	return o.sdk.EnsureGlobalDirectory()
}

// ListPrograms returns all programs in the configuration
func (o *Ouroboros) ListPrograms() []config.Program {
	programs := o.sdk.ListPrograms()
	return toInternalPrograms(programs)
}

// GetCompileArgs returns the compile arguments from configuration
func (o *Ouroboros) GetCompileArgs() []string {
	return o.sdk.GetCompileArgs()
}

// SetCompileArgs sets the compile arguments
func (o *Ouroboros) SetCompileArgs(args []string) {
	o.sdk.SetCompileArgs(args)
}

// Conversion helpers

func toSDKProgram(p *config.Program) *sdk.Program {
	var metadata *sdk.ProgramMetadata
	if p.Metadata != nil {
		metadata = &sdk.ProgramMetadata{
			HiddenOnFlow: p.Metadata.HiddenOnFlow,
		}
	}

	return &sdk.Program{
		Name:       p.Name,
		ID:         p.ID,
		IsMain:     p.IsMain,
		Metadata:   metadata,
		Entrypoint: p.Entrypoint,
	}
}

func toInternalProgram(p *sdk.Program) *config.Program {
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

func toSDKPrograms(programs []config.Program) []sdk.Program {
	result := make([]sdk.Program, len(programs))
	for i := range programs {
		result[i] = *toSDKProgram(&programs[i])
	}
	return result
}

func toInternalPrograms(programs []sdk.Program) []config.Program {
	result := make([]config.Program, len(programs))
	for i := range programs {
		result[i] = *toInternalProgram(&programs[i])
	}
	return result
}
