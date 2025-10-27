package cmd

import (
	"bytes"
	_ "embed"
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

		Debug("Adding new program", "name", progName)

		ouroborosConfig, err := ReadConfig()
		if err != nil {
			Fatal("Failed to read config", "error", err)
		}

		for _, p := range ouroborosConfig.Programs {
			if p.Name == progName {
				Fatal("Program already exists", "name", progName)
			}
		}

		progDir := filepath.Join(srcDir, progName)

		Debug("Creating program directory", "path", progDir)

		if err := os.Mkdir(progDir, 0755); err != nil {
			Fatal("Failed to create program directory", "path", progDir, "error", err)
		}

		Debug("Parsing main.c template")

		tmpl, err := template.New("main.c").Parse(mainCTemplate)
		if err != nil {
			Fatal("Failed to parse template", "error", err)
		}

		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, map[string]string{"progName": progName}); err != nil {
			Fatal("Failed to execute template", "error", err)
		}

		mainCPath := filepath.Join(progDir, entryPointFile)

		Debug("Writing main.c file", "path", mainCPath)

		if err := os.WriteFile(mainCPath, buf.Bytes(), 0644); err != nil {
			Fatal("Failed to write main.c file", "path", mainCPath, "error", err)
		}

		nextID := 1000
		for _, p := range ouroborosConfig.Programs {
			if p.ID > nextID {
				nextID = p.ID
			}
		}
		nextID++

		Debug("Assigning program ID", "id", nextID)

		newProg := Program{Name: progName, ID: nextID}

		ouroborosConfig.Programs = append(ouroborosConfig.Programs, newProg)

		Debug("Updating configuration file")

		if err := WriteConfig(ouroborosConfig); err != nil {
			Fatal("Failed to write config", "error", err)
		}

		Debug("Running post-program-add hooks")

		if err := RunPostProgramAdd(ouroborosConfig); err != nil {
			Fatal("Failed to run post-program-add hooks", "error", err)
		}

		Info("Program added successfully", "name", progName, "id", nextID)
	},
}

