package utils

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/PacketStream-LLC/ouroboros/internal/config"
	"github.com/PacketStream-LLC/ouroboros/internal/logger"
)

// DetectLibBPF checks if libbpf-dev is installed on the system
// Exits with fatal error if not found
// Can be skipped with --ignore-libbpf-detection flag
func DetectLibBPF() {
	// Check if detection should be skipped (flag will be checked by caller)
	if _, err := os.Stat("/usr/include/bpf/bpf.h"); os.IsNotExist(err) {
		logger.Fatal("libbpf-dev is not installed. Please install it first (use --ignore-libbpf-detection to bypass)")
	}
}

// FindBpftool locates the bpftool binary on the system
// Returns the path to bpftool or an error if not found
func FindBpftool() (string, error) {
	// Check common locations
	locations := []string{
		"/usr/sbin/bpftool",
		"/usr/local/sbin/bpftool",
		"/sbin/bpftool",
	}

	for _, loc := range locations {
		if _, err := os.Stat(loc); err == nil {
			return loc, nil
		}
	}

	// Try to find in PATH
	path, err := exec.LookPath("bpftool")
	if err != nil {
		return "", fmt.Errorf("bpftool not found in standard locations or PATH")
	}

	return path, nil
}

// ExecBpftool executes bpftool with the given arguments
// Pipes stdout, stderr, and stdin through to the current process
// Exits with the same exit code as bpftool
func ExecBpftool(bpftoolPath string, args []string) {
	cmd := exec.Command(bpftoolPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Printf("Error executing bpftool: %v\n", err)
		os.Exit(1)
	}
}

// ResolveProjectPath converts a path to absolute path relative to project root
// Returns absolute path from project root
func ResolveProjectPath(relativePath string) (string, error) {
	projectRoot, err := config.FindProjectRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(projectRoot, relativePath), nil
}

// ResolveCwdPath converts a path to absolute path relative to current working directory
// If path is already absolute, returns it as-is
func ResolveCwdPath(path string) (string, error) {
	if filepath.IsAbs(path) {
		return path, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current directory: %w", err)
	}
	return filepath.Join(cwd, path), nil
}

// WithProjectRoot executes a function with the working directory changed to project root
// Automatically restores the original working directory after execution
func WithProjectRoot(fn func() error) error {
	// Find project root from CWD
	projectRoot, err := config.FindProjectRoot()
	if err != nil {
		return err
	}
	return WithProjectRootPath(projectRoot, fn)
}

// WithProjectRootPath executes a function with the working directory changed to specified project root
// Automatically restores the original working directory after execution
func WithProjectRootPath(projectRoot string, fn func() error) error {
	// Save current directory
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}

	if err := os.Chdir(projectRoot); err != nil {
		return fmt.Errorf("failed to change to project root: %w", err)
	}

	// Ensure we restore original directory
	defer func() {
		if err := os.Chdir(cwd); err != nil {
			logger.Error("Failed to restore working directory", "error", err)
		}
	}()

	return fn()
}
