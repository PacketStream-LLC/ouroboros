package ouroboros

import (
	"bytes"
	"fmt"
	"os"
	"text/template"

	"github.com/PacketStream-LLC/ouroboros/pkg/constants"
)

// CreateProgramFromTemplate creates a new program directory and main.c from template.
// The template should use {{.ProgramName}} for the program name placeholder.
func (o *Ouroboros) CreateProgramFromTemplate(progName string, tmpl string) error {
	// Ensure directory exists
	if err := o.EnsureProgramDirectory(progName); err != nil {
		return err
	}

	// Parse template
	t, err := template.New("main.c").Parse(tmpl)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	// Execute template
	var buf bytes.Buffer
	if err := t.Execute(&buf, struct{ ProgramName string }{ProgramName: progName}); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	// Write main.c file
	mainCPath := o.GetProgramMainFile(progName)
	if err := os.WriteFile(mainCPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write main.c file %s: %w", mainCPath, err)
	}

	return nil
}

// AddNewProgram is a high-level operation that adds a program with all necessary setup.
// It creates the program directory, generates the main.c file from the template,
// assigns an ID, and saves the configuration.
func (o *Ouroboros) AddNewProgram(progName string, mainCTemplate string) error {
	// Check if program already exists
	if o.GetProgram(progName) != nil {
		return fmt.Errorf("program %s already exists", progName)
	}

	// Create program directory and files
	if err := o.CreateProgramFromTemplate(progName, mainCTemplate); err != nil {
		return err
	}

	// Get next ID
	nextID := o.GetNextProgramID()

	// Add to config
	newProg := Program{
		Name: progName,
		ID:   nextID,
	}

	if err := o.AddProgram(newProg); err != nil {
		return err
	}

	// Save config
	if err := o.SaveConfig(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	return nil
}

// InitializeProject creates a new Ouroboros project structure with the given main program name.
// It creates the necessary directories (src, target, src/_ouroboros) and a default configuration.
func InitializeProject(mainProgName string) (*Ouroboros, error) {
	return InitializeProjectWithMap(mainProgName, "")
}

// InitializeProjectWithMap creates a new Ouroboros project structure with custom program map name.
// It creates the necessary directories (src, target, src/_ouroboros) and a default configuration.
// If programMapName is empty, no custom program map name will be set.
func InitializeProjectWithMap(mainProgName, programMapName string) (*Ouroboros, error) {
	// Create source directory
	if err := os.MkdirAll(constants.SrcDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create src directory: %w", err)
	}

	// Create target directory
	if err := os.MkdirAll(constants.TargetDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create target directory: %w", err)
	}

	// Create ouroboros global directory
	if err := os.MkdirAll(constants.OuroborosGlobalDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create ouroboros global directory: %w", err)
	}

	// Create default configuration
	cfg := &Config{
		Programs: []Program{
			{Name: mainProgName, ID: 1, IsMain: true},
		},
		CompileArgs: []string{"-Wall"},
		ProgramMap:  programMapName, // Set custom program map name if provided
	}

	o := NewWithConfig(cfg)

	// Save config
	if err := o.SaveConfig(); err != nil {
		return nil, fmt.Errorf("failed to write config: %w", err)
	}

	return o, nil
}

// CleanBuildArtifacts removes all build artifacts including the target directory
// and the global ouroboros directory.
func (o *Ouroboros) CleanBuildArtifacts() error {
	// Get absolute target directory
	targetDir, err := o.GetTargetDir()
	if err != nil {
		targetDir = constants.TargetDir
	}

	// Remove target directory
	if err := os.RemoveAll(targetDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove target directory: %w", err)
	}

	// Get absolute global directory
	globalDir, err := o.GetOuroborosGlobalDir()
	if err != nil {
		globalDir = constants.OuroborosGlobalDir
	}

	// Remove ouroboros global directory
	if err := os.RemoveAll(globalDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove ouroboros global directory: %w", err)
	}

	return nil
}
