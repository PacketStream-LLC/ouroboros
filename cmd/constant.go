package cmd

import (
	"path/filepath"

	"github.com/cilium/ebpf"
)

var srcDir string = "src"
var ouroborosGlobalDir string = filepath.Join(srcDir, "_ouroboros")

var targetDir string = "target"

var bpfBaseDir string = "/sys/fs/bpf"
var bpfMapOptions = ebpf.MapOptions{
	PinPath: bpfBaseDir,
}
