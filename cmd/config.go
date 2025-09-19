package cmd

import (
	"encoding/json"
	"fmt"
	"os"
)

const configFileName = "ouroboros.json"

func ReadConfig() (*OuroborosConfig, error) {
	jsonFile, err := os.Open(configFileName)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", configFileName, err)
	}
	defer jsonFile.Close()

	var ouroborosConfig OuroborosConfig
	decoder := json.NewDecoder(jsonFile)
	if err := decoder.Decode(&ouroborosConfig); err != nil {
		return nil, fmt.Errorf("failed to decode %s: %w", configFileName, err)
	}

	return &ouroborosConfig, nil
}

func WriteConfig(config *OuroborosConfig) error {
	file, err := os.Create(configFileName)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", configFileName, err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(config); err != nil {
		return fmt.Errorf("failed to encode %s: %w", configFileName, err)
	}

	return nil
}
