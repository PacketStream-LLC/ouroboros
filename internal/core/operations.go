package core

import (
	"bytes"
	"fmt"
	"os"
	"text/template"

	"github.com/PacketStream-LLC/ouroboros/internal/config"
	"github.com/PacketStream-LLC/ouroboros/pkg/constants"
	"github.com/PacketStream-LLC/ouroboros/internal/logger"
)

// CreateProgramFromTemplate creates a new program directory and main.c from template
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

	logger.Debug("Created main.c from template", "path", mainCPath)
	return nil
}

// AddNewProgram is a high-level operation that adds a program with all necessary setup
func (o *Ouroboros) AddNewProgram(progName string, mainCTemplate string) error {
	logger.Debug("Adding new program", "name", progName)

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
	logger.Debug("Assigning program ID", "id", nextID)

	// Add to config
	newProg := config.Program{
		Name: progName,
		ID:   nextID,
	}

	if err := o.AddProgram(newProg); err != nil {
		return err
	}

	// Save config
	logger.Debug("Updating configuration file")
	if err := o.SaveConfig(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	logger.Info("Program added successfully", "name", progName, "id", nextID)
	return nil
}

// InitializeProject creates a new Ouroboros project structure
func InitializeProject(mainProgName string) (*Ouroboros, error) {
	return InitializeProjectWithMap(mainProgName, "")
}

// InitializeProjectWithMap creates a new Ouroboros project structure with custom program map name
func InitializeProjectWithMap(mainProgName, programMapName string) (*Ouroboros, error) {
	logger.Debug("Creating source directory")
	if err := os.MkdirAll(constants.SrcDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create src directory: %w", err)
	}

	logger.Debug("Creating target directory")
	if err := os.MkdirAll(constants.TargetDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create target directory: %w", err)
	}

	logger.Debug("Creating ouroboros global directory")
	if err := os.MkdirAll(constants.OuroborosGlobalDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create ouroboros global directory: %w", err)
	}

	// Create default configuration
	logger.Debug("Creating default configuration")
	cfg := &config.OuroborosConfig{
		Programs: []config.Program{
			{Name: mainProgName, ID: 1, IsMain: true},
		},
		CompileArgs: []string{"-Wall"},
		ProgramMap:  programMapName, // Set custom program map name if provided
	}

	// Save config
	logger.Debug("Writing configuration file")
	if err := config.WriteConfig(cfg); err != nil {
		return nil, fmt.Errorf("failed to write config: %w", err)
	}

	// Create Ouroboros instance
	o := NewWithConfig(cfg)
	return o, nil
}

// CleanBuildArtifacts removes all build artifacts
func (o *Ouroboros) CleanBuildArtifacts() error {
	logger.Debug("Removing target directory")

	if err := os.RemoveAll(constants.TargetDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove target directory: %w", err)
	}

	logger.Debug("Removing ouroboros global directory")
	if err := os.RemoveAll(constants.OuroborosGlobalDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove ouroboros global directory: %w", err)
	}

	logger.Info("Build artifacts cleaned successfully")
	return nil
}
