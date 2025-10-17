package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new ouroboros project",
	Run: func(cmd *cobra.Command, args []string) {
		if err := os.Mkdir(srcDir, 0755); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if err := os.Mkdir(targetDir, 0755); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Create src/_global directory
		if err := os.MkdirAll(filepath.Join(srcDir, "_global"), 0755); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Create src/_ouroboros directory
		if err := os.MkdirAll(ouroborosGlobalDir, 0755); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		ouroborosConfig := &OuroborosConfig{
			Programs: []Program{
				{Name: "main", ID: 1, IsMain: true},
			},
			CompileArgs: []string{"-Wall"},
		}

		if err := WriteConfig(ouroborosConfig); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if err := GenerateProgramsHeader(ouroborosConfig); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fmt.Println("ouroboros project created successfully.")
	},
}

func init() {
	RootCmd.AddCommand(createCmd)
}
