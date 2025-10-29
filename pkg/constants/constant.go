package constants

import (
	"path/filepath"
)

var SrcDir string = "src"
var OuroborosGlobalDir string = filepath.Join(SrcDir, "_ouroboros")

var TargetDir string = "target"
var EntryPointFile string = "main.c"

// Default values for project creation
const (
	DefaultMainProgramName = "main"
	DefaultGlobalDirName   = "_global"
)
