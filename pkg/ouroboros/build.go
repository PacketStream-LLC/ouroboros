package ouroboros

import (
	"fmt"
	"io"
	"os"
	"os/exec"
)

// BuildOptions contains options for building eBPF programs.
type BuildOptions struct {
	// Stdout is where to write build output (optional, defaults to discard)
	Stdout io.Writer
	// Stderr is where to write build errors (optional, defaults to discard)
	Stderr io.Writer
	// AdditionalArgs are additional arguments to pass to clang
	AdditionalArgs []string
}

// BuildProgram compiles a single eBPF program.
// It runs clang with the appropriate flags to compile the program's main.c
// into an eBPF object file in the target directory.
func (o *Ouroboros) BuildProgram(progName string, opts *BuildOptions) error {
	if opts == nil {
		opts = &BuildOptions{}
	}

	prog := o.GetProgram(progName)
	if prog == nil {
		return fmt.Errorf("program %s not found", progName)
	}

	// Ensure target directory exists
	if err := o.EnsureTargetDirectory(); err != nil {
		return err
	}

	// Get paths
	mainC := o.GetProgramMainFile(progName)
	outputObj := o.GetProgramObjectPath(progName)

	// Check if source file exists
	if _, err := os.Stat(mainC); os.IsNotExist(err) {
		return fmt.Errorf("source file not found: %s", mainC)
	}

	// Build clang arguments
	args := []string{
		"-O2",
		"-g",
		"-target", "bpf",
		"-c", mainC,
		"-o", outputObj,
		"-Isrc/",
	}

	// Add config compile args
	args = append(args, o.GetCompileArgs()...)

	// Add additional args from options
	if len(opts.AdditionalArgs) > 0 {
		args = append(args, opts.AdditionalArgs...)
	}

	// Run clang
	cmd := exec.Command("clang", args...)

	// Set output writers if provided
	if opts.Stdout != nil {
		cmd.Stdout = opts.Stdout
	}
	if opts.Stderr != nil {
		cmd.Stderr = opts.Stderr
	}

	// If no output writers, capture output for error reporting
	if opts.Stdout == nil && opts.Stderr == nil {
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("clang failed for %s: %w\n%s", progName, err, output)
		}
		return nil
	}

	// Run with output writers
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("clang failed for %s: %w", progName, err)
	}

	return nil
}

// BuildAll compiles all eBPF programs in the project.
// Returns a map of program names to errors (nil if successful).
func (o *Ouroboros) BuildAll(opts *BuildOptions) map[string]error {
	programs := o.ListPrograms()
	results := make(map[string]error)

	for _, prog := range programs {
		err := o.BuildProgram(prog.Name, opts)
		results[prog.Name] = err
	}

	return results
}

// BuildAllOrFail compiles all eBPF programs and returns an error if any fail.
func (o *Ouroboros) BuildAllOrFail(opts *BuildOptions) error {
	results := o.BuildAll(opts)

	var failed []string
	for name, err := range results {
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", name, err))
		}
	}

	if len(failed) > 0 {
		return fmt.Errorf("build failed for programs:\n%s", failed)
	}

	return nil
}

// IsProgramBuilt checks if a program has been built (object file exists).
func (o *Ouroboros) IsProgramBuilt(progName string) bool {
	objPath := o.GetProgramObjectPath(progName)
	_, err := os.Stat(objPath)
	return err == nil
}

// GetProgramSize returns the size of a compiled program object in bytes.
// Returns 0 if the program hasn't been built.
func (o *Ouroboros) GetProgramSize(progName string) int64 {
	objPath := o.GetProgramObjectPath(progName)
	info, err := os.Stat(objPath)
	if err != nil {
		return 0
	}
	return info.Size()
}

// CleanProgram removes the compiled object for a specific program.
func (o *Ouroboros) CleanProgram(progName string) error {
	objPath := o.GetProgramObjectPath(progName)
	llPath := o.GetProgramLLPath(progName)

	// Remove object file
	if err := os.Remove(objPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove %s: %w", objPath, err)
	}

	// Remove LLVM IR file if it exists
	if err := os.Remove(llPath); err != nil && !os.IsNotExist(err) {
		// Don't fail if LLVM IR doesn't exist
	}

	return nil
}

// RebuildProgram removes old build artifacts and rebuilds a program.
func (o *Ouroboros) RebuildProgram(progName string, opts *BuildOptions) error {
	if err := o.CleanProgram(progName); err != nil {
		return err
	}
	return o.BuildProgram(progName, opts)
}

// CompileToLLVMIR compiles a program to LLVM IR (.ll file) instead of object code.
// This is useful for analysis and optimization.
func (o *Ouroboros) CompileToLLVMIR(progName string, opts *BuildOptions) error {
	if opts == nil {
		opts = &BuildOptions{}
	}

	prog := o.GetProgram(progName)
	if prog == nil {
		return fmt.Errorf("program %s not found", progName)
	}

	if err := o.EnsureTargetDirectory(); err != nil {
		return err
	}

	mainC := o.GetProgramMainFile(progName)
	outputLL := o.GetProgramLLPath(progName)

	// Check if source exists
	if _, err := os.Stat(mainC); os.IsNotExist(err) {
		return fmt.Errorf("source file not found: %s", mainC)
	}

	// Build clang arguments for LLVM IR
	args := []string{
		"-O2",
		"-g",
		"-target", "bpf",
		"-S", "-emit-llvm", // Generate LLVM IR
		mainC,
		"-o", outputLL,
		"-Isrc/",
	}

	args = append(args, o.GetCompileArgs()...)

	if len(opts.AdditionalArgs) > 0 {
		args = append(args, opts.AdditionalArgs...)
	}

	// Run clang
	cmd := exec.Command("clang", args...)

	// Set output writers if provided
	if opts.Stdout != nil {
		cmd.Stdout = opts.Stdout
	}
	if opts.Stderr != nil {
		cmd.Stderr = opts.Stderr
	}

	// If no output writers, capture output for error reporting
	if opts.Stdout == nil && opts.Stderr == nil {
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("clang IR generation failed for %s: %w\n%s", progName, err, output)
		}
		return nil
	}

	// Run with output writers
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("clang IR generation failed for %s: %w", progName, err)
	}

	return nil
}
