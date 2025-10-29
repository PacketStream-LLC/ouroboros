package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	configFileName        = "ouroboros.json"
	maxConfigSearchLevels = 10 // Maximum number of parent directories to search
)

// FindConfigPath searches for the config file starting from current directory
// and traversing up parent directories until found or limits are reached
func FindConfigPath() (string, error) {
	// Get current working directory
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current directory: %w", err)
	}

	currentDir := cwd
	for i := 0; i < maxConfigSearchLevels; i++ {
		configPath := filepath.Join(currentDir, configFileName)

		// Check if config file exists
		if _, err := os.Stat(configPath); err == nil {
			return configPath, nil
		}

		// Get parent directory
		parentDir := filepath.Dir(currentDir)

		// Check if we've reached the root
		if parentDir == currentDir {
			break
		}

		currentDir = parentDir
	}

	return "", fmt.Errorf("config file '%s' not found in current directory or any parent directories (searched up to %d levels)", configFileName, maxConfigSearchLevels)
}

// FindProjectRoot returns the directory containing ouroboros.json
func FindProjectRoot() (string, error) {
	configPath, err := FindConfigPath()
	if err != nil {
		return "", err
	}
	return filepath.Dir(configPath), nil
}

func ReadConfig() (*OuroborosConfig, error) {
	configPath, err := FindConfigPath()
	if err != nil {
		return nil, err
	}

	jsonFile, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", configPath, err)
	}
	defer jsonFile.Close()

	var ouroborosConfig OuroborosConfig
	decoder := json.NewDecoder(jsonFile)
	if err := decoder.Decode(&ouroborosConfig); err != nil {
		return nil, fmt.Errorf("failed to decode %s: %w", configPath, err)
	}

	return &ouroborosConfig, nil
}

func WriteConfig(config *OuroborosConfig) error {
	// Write to project root, not CWD
	projectRoot, err := FindProjectRoot()
	if err != nil {
		// If no project root found, write to CWD (for new project creation)
		projectRoot = "."
	}

	configPath := filepath.Join(projectRoot, configFileName)
	file, err := os.Create(configPath)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", configPath, err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(config); err != nil {
		return fmt.Errorf("failed to encode %s: %w", configPath, err)
	}

	return nil
}
