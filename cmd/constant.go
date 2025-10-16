package cmd

import "github.com/cilium/ebpf"

var srcDir string = "src"
var ouroborosGlobalDir string = srcDir + "/_ouroboros"

var targetDir string = "target"

var bpfBaseDir string = "/sys/fs/bpf"
var bpfMapOptions = ebpf.MapOptions{
	PinPath: bpfBaseDir,
}
