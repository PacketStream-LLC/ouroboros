package cli

import (
	"github.com/PacketStream-LLC/ouroboros/internal/config"
)

func RunPostProgramAdd(config *config.OuroborosConfig) error {
	if err := GenerateProgramsHeader(config); err != nil {
		return err
	}
	if err := GenerateGitignore(); err != nil {
		return err
	}

	return nil
}
