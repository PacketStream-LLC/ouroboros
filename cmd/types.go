package cmd

type SharedMapConfig struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	KeySize    uint32 `json:"key_size"`
	ValueSize  uint32 `json:"value_size"`
	MaxEntries uint32 `json:"max_entries"`
	Comment    string `json:"comment,omitempty"`
}

type Program struct {
	Name     string           `json:"name"`
	ID       int              `json:"id"`
	IsMain   bool             `json:"is_main,omitempty"`
	Metadata *ProgramMetadata `json:"metadata,omitempty"`
}

type ProgramMetadata struct {
	HiddenOnFlow bool `json:"hidden_on_flow,omitempty"`
}

type OuroborosConfig struct {
	Programs      []Program         `json:"programs"`
	SharedMaps    []SharedMapConfig `json:"shared_maps,omitempty"`
	CompileArgs   []string          `json:"compile_args"`
	ProgramMap    string            `json:"program_map,omitempty"`
	ProgramPrefix string            `json:"program_prefix,omitempty"`
}

func (c *OuroborosConfig) GetMainProgram() *Program {
	for _, p := range c.Programs {
		if p.IsMain {
			return &p
		}
	}
	return nil
}

func (c *OuroborosConfig) GetProgramMap() string {
	if c.ProgramMap != "" {
		return c.ProgramMap
	}

	return "ouro_progmaps"
}
