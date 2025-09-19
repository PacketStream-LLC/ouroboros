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

//go:embed templates/maps.h.tmpl
var mapsHeaderTemplateContent string

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
			fmt.Println(err)
			os.Exit(1)
		}

		if err := GenerateProgramsHeader(ouroborosConfig); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if err := GenerateMapsHeader(ouroborosConfig); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if ide != "" {
			switch ide {
			case "vscode":
				if err := GenerateVSCodeConfig(); err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
			case "intellij":
				if err := GenerateCLionConfig(); err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
			default:
				fmt.Printf("unsupported ide: %s\n", ide)
				os.Exit(1)
			}
		}

		fmt.Println("Generated _ouroboros files successfully.")
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

	fmt.Printf("Generated %s\n", programsHeaderPath)
	return nil
}

func GenerateMapsHeader(config *OuroborosConfig) error {
	globalDir := ouroborosGlobalDir

	if err := os.MkdirAll(globalDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", globalDir, err)
	}

	mapsHeaderPath := filepath.Join(globalDir, "maps.h")
	file, err := os.Create(mapsHeaderPath)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", mapsHeaderPath, err)
	}
	defer file.Close()

	// Create a temporary config to pass to the template with BPFTypeString
	type TempSharedMapConfig struct {
		SharedMapConfig
		BPFTypeString string
	}

	type TempOuroborosConfig struct {
		*OuroborosConfig
		SharedMaps []TempSharedMapConfig
	}

	tempConfig := TempOuroborosConfig{OuroborosConfig: config}
	for _, sm := range config.SharedMaps {
		tempSm := TempSharedMapConfig{SharedMapConfig: sm}
		switch sm.Type {
		case "Hash":
			tempSm.BPFTypeString = "BPF_MAP_TYPE_HASH"
		case "Array":
			tempSm.BPFTypeString = "BPF_MAP_TYPE_ARRAY"
		case "ProgramArray":
			tempSm.BPFTypeString = "BPF_MAP_TYPE_PROG_ARRAY"
		case "PerfEventArray":
			tempSm.BPFTypeString = "BPF_MAP_TYPE_PERF_EVENT_ARRAY"
		case "PerCPUHash":
			tempSm.BPFTypeString = "BPF_MAP_TYPE_PERCPU_HASH"
		case "PerCPUArray":
			tempSm.BPFTypeString = "BPF_MAP_TYPE_PERCPU_ARRAY"
		case "StackTrace":
			tempSm.BPFTypeString = "BPF_MAP_TYPE_STACK_TRACE"
		case "CGroupArray":
			tempSm.BPFTypeString = "BPF_MAP_TYPE_CGROUP_ARRAY"
		case "LRUHash":
			tempSm.BPFTypeString = "BPF_MAP_TYPE_LRU_HASH"
		case "LRUCPUHash":
			tempSm.BPFTypeString = "BPF_MAP_TYPE_LRU_CPU_HASH"
		case "LPMTrie":
			tempSm.BPFTypeString = "BPF_MAP_TYPE_LPM_TRIE"
		case "ArrayOfMaps":
			tempSm.BPFTypeString = "BPF_MAP_TYPE_ARRAY_OF_MAPS"
		case "HashOfMaps":
			tempSm.BPFTypeString = "BPF_MAP_TYPE_HASH_OF_MAPS"
		case "DevMap":
			tempSm.BPFTypeString = "BPF_MAP_TYPE_DEVMAP"
		case "SockMap":
			tempSm.BPFTypeString = "BPF_MAP_TYPE_SOCKMAP"
		case "CPUMap":
			tempSm.BPFTypeString = "BPF_MAP_TYPE_CPUMAP"
		case "XSKMap":
			tempSm.BPFTypeString = "BPF_MAP_TYPE_XSKMAP"
		case "RingBuf":
			tempSm.BPFTypeString = "BPF_MAP_TYPE_RINGBUF"
		case "InodeStorage":
			tempSm.BPFTypeString = "BPF_MAP_TYPE_INODE_STORAGE"
		case "TaskStorage":
			tempSm.BPFTypeString = "BPF_MAP_TYPE_TASK_STORAGE"
		case "CGroupStorage":
			tempSm.BPFTypeString = "BPF_MAP_TYPE_CGROUP_STORAGE"
		case "SyscallOps":
			tempSm.BPFTypeString = "BPF_MAP_TYPE_SYSCALL_OPS"
		case "StructOps":
			tempSm.BPFTypeString = "BPF_MAP_TYPE_STRUCT_OPS"
		case "PCPUArray":
			tempSm.BPFTypeString = "BPF_MAP_TYPE_PCPU_ARRAY"
		default:
			return fmt.Errorf("unsupported map type: %s", sm.Type)
		}
		tempConfig.SharedMaps = append(tempConfig.SharedMaps, tempSm)
	}

	tmpl, err := template.New("maps_header").Parse(mapsHeaderTemplateContent)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	if err := tmpl.Execute(file, tempConfig); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	fmt.Printf("Generated %s\n", mapsHeaderPath)
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

	fmt.Printf("Generated %s\n", gitignorePath)
	return nil
}

func GenerateVSCodeConfig() error {
	vscodeDir := ".vscode"
	if err := os.MkdirAll(vscodeDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", vscodeDir, err)
	}

	cCppPropertiesPath := filepath.Join(vscodeDir, "c_cpp_properties.json")
	if _, err := os.Stat(cCppPropertiesPath); err == nil && !overwrite {
		fmt.Printf("file %s already exists, use --overwrite to force overwrite\n", cCppPropertiesPath)
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

	fmt.Printf("Generated %s\n", cCppPropertiesPath)
	return nil
}

func GenerateCLionConfig() error {
	clangdPath := ".clangd"
	if _, err := os.Stat(clangdPath); err == nil && !overwrite {
		fmt.Printf("file %s already exists, use --overwrite to force overwrite\n", clangdPath)
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

	fmt.Printf("Generated %s\n", clangdPath)
	return nil
}

func init() {
	RootCmd.AddCommand(generateCmd)
	generateCmd.Flags().StringVar(&ide, "ide", "", "Generate IDE configuration files (vscode, intellij)")
	generateCmd.Flags().BoolVar(&overwrite, "overwrite", false, "Overwrite existing IDE configuration files")
}
