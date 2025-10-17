package cmd

import (
	"path/filepath"
)

var srcDir string = "src"
var ouroborosGlobalDir string = filepath.Join(srcDir, "_ouroboros")

var targetDir string = "target"
var entryPointFile string = "main.c"
