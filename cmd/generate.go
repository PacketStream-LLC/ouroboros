package cmd

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"github.com/spf13/cobra"
)

//go:embed templates/programs.h.tmpl
var programsHeaderTemplateContent string

//go:embed templates/.gitignore.tmpl
var gitignoreTemplateContent string

//go:embed templates/c_cpp_properties.json.tmpl
var cCppPropertiesTemplateContent string

//go:embed templates/clangd.tmpl
var clangdTemplateContent string

var ide string
var overwrite bool

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate _ouroboros related files",
	Run: func(cmd *cobra.Command, args []string) {

		ouroborosConfig, err := ReadConfig()
		if err != nil {
			Fatal("Failed to read config", "error", err)
		}

		Debug("Generating programs header")
		if err := GenerateProgramsHeader(ouroborosConfig); err != nil {
			Fatal("Failed to generate programs header", "error", err)
		}

		if ide != "" {
			Debug("Generating IDE configuration", "ide", ide)
			switch ide {
			case "vscode":
				if err := GenerateVSCodeConfig(); err != nil {
					Fatal("Failed to generate VS Code config", "error", err)
				}
			case "intellij":
				if err := GenerateCLionConfig(); err != nil {
					Fatal("Failed to generate CLion config", "error", err)
				}
			default:
				Fatal("Unsupported IDE", "ide", ide)
			}
		}

		Info("Generated _ouroboros files successfully")
	},
}

func GenerateProgramsHeader(config *OuroborosConfig) error {
	globalDir := ouroborosGlobalDir

	if err := os.MkdirAll(globalDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", globalDir, err)
	}

	programsHeaderPath := filepath.Join(globalDir, "programs.h")
	file, err := os.Create(programsHeaderPath)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", programsHeaderPath, err)
	}
	defer file.Close()

	tmpl, err := template.New("programs_header").Parse(programsHeaderTemplateContent)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	if err := tmpl.Execute(file, config); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	Info("Generated programs header", "path", programsHeaderPath)
	return nil
}

func GenerateGitignore() error {
	gitignorePath := ".gitignore"

	gitignoreFile, err := os.Create(gitignorePath)
	if err != nil {
		if os.IsExist(err) {
			// .gitignore already exists, skip creation
			return nil
		}

		return fmt.Errorf("failed to create %s: %w", gitignorePath, err)
	}

	defer gitignoreFile.Close()
	gitignoreTmpl, err := template.New("gitignore").Parse(gitignoreTemplateContent)
	if err != nil {
		return fmt.Errorf("failed to parse gitignore template: %w", err)
	}

	if err := gitignoreTmpl.Execute(gitignoreFile, nil); err != nil {
		return fmt.Errorf("failed to execute gitignore template: %w", err)
	}

	Info("Generated gitignore", "path", gitignorePath)
	return nil
}

func GenerateVSCodeConfig() error {
	vscodeDir := ".vscode"
	if err := os.MkdirAll(vscodeDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", vscodeDir, err)
	}

	cCppPropertiesPath := filepath.Join(vscodeDir, "c_cpp_properties.json")
	if _, err := os.Stat(cCppPropertiesPath); err == nil && !overwrite {
		Info("File already exists, use --overwrite to force overwrite", "path", cCppPropertiesPath)
		return nil
	}

	file, err := os.Create(cCppPropertiesPath)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", cCppPropertiesPath, err)
	}
	defer file.Close()

	tmpl, err := template.New("c_cpp_properties.json").Parse(cCppPropertiesTemplateContent)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	if err := tmpl.Execute(file, nil); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	Info("Generated VS Code config", "path", cCppPropertiesPath)
	return nil
}

func GenerateCLionConfig() error {
	clangdPath := ".clangd"
	if _, err := os.Stat(clangdPath); err == nil && !overwrite {
		Info("File already exists, use --overwrite to force overwrite", "path", clangdPath)
		return nil
	}

	file, err := os.Create(clangdPath)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", clangdPath, err)
	}
	defer file.Close()

	tmpl, err := template.New("clangd").Parse(clangdTemplateContent)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	if err := tmpl.Execute(file, map[string]string{"IncludePath": filepath.Join(wd, "src")}); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	Info("Generated CLion config", "path", clangdPath)
	return nil
}

