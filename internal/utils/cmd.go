package utils

import "github.com/spf13/cobra"

func IsVerbose(cmd *cobra.Command) bool {
	verbose, err := cmd.Root().PersistentFlags().GetBool("verbose")
	if err != nil {
		return false
	}

	return verbose
}
