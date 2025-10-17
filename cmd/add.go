package cmd

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"github.com/spf13/cobra"
)

//go:embed templates/main.c.tmpl
var mainCTemplate string

var addCmd = &cobra.Command{
	Use:   "add [prog_name]",
	Short: "Add a new eBPF program to the project",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		progName := args[0]

		ouroborosConfig, err := ReadConfig()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		for _, p := range ouroborosConfig.Programs {
			if p.Name == progName {
				fmt.Printf("program '%s' already exists.\n", progName)
				os.Exit(1)
			}
		}

		progDir := filepath.Join(srcDir, progName)

		if err := os.Mkdir(progDir, 0755); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		tmpl, err := template.New("main.c").Parse(mainCTemplate)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, map[string]string{"progName": progName}); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		mainCPath := filepath.Join(progDir, entryPointFile)
		if err := os.WriteFile(mainCPath, buf.Bytes(), 0644); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		nextID := 1000
		for _, p := range ouroborosConfig.Programs {
			if p.ID > nextID {
				nextID = p.ID
			}
		}
		nextID++

		newProg := Program{Name: progName, ID: nextID}

		ouroborosConfig.Programs = append(ouroborosConfig.Programs, newProg)

		if err := WriteConfig(ouroborosConfig); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if err := RunPostProgramAdd(ouroborosConfig); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fmt.Printf("program '%s' added successfully.\n", progName)
	},
}

func init() {
	RootCmd.AddCommand(addCmd)
}
