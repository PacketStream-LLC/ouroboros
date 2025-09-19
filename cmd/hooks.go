package cmd

func RunPostProgramAdd(config *OuroborosConfig) error {
	if err := GenerateProgramsHeader(config); err != nil {
		return err
	}

	if err := GenerateGitignore(); err != nil {
		return err
	}

	return nil
}
