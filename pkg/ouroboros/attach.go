package ouroboros

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/PacketStream-LLC/ouroboros/internal/logger"
	"github.com/cilium/ebpf/link"
)

// AttachMode specifies how to attach an XDP program.
type AttachMode int

const (
	// AttachModeGeneric uses generic XDP (slower but works everywhere)
	AttachModeGeneric AttachMode = iota
	// AttachModeNative uses native XDP (faster, driver support required)
	AttachModeNative
	// AttachModeOffload uses hardware offload (fastest, hardware support required)
	AttachModeOffload
)

// AttachOptions contains options for attaching programs.
type AttachOptions struct {
	// Mode specifies the XDP attach mode
	Mode AttachMode
	// Replace allows replacing an existing attached program
	Replace bool
}

// AttachedProgram represents a program attached to an interface.
type AttachedProgram struct {
	Program   *LoadedProgram
	Interface string
	Link      link.Link
}

// AttachToInterface attaches a loaded XDP program to a network interface.
// The program must be loaded before calling this method.
func (o *Ouroboros) AttachToInterface(loaded *LoadedProgram, ifaceName string, opts *AttachOptions) (*AttachedProgram, error) {
	if loaded == nil || loaded.Program == nil {
		return nil, fmt.Errorf("program not loaded")
	}

	if opts == nil {
		opts = &AttachOptions{
			Mode: AttachModeNative,
		}
	}

	// Get interface
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}

	// Convert attach mode to link flags
	var flags link.XDPAttachFlags
	switch opts.Mode {
	case AttachModeGeneric:
		flags = link.XDPGenericMode
	case AttachModeNative:
		flags = link.XDPDriverMode
	case AttachModeOffload:
		flags = link.XDPOffloadMode
	default:
		flags = link.XDPDriverMode
	}

	// Attach the program
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   loaded.Program,
		Interface: iface.Index,
		Flags:     flags,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach to %s: %w", ifaceName, err)
	}

	// Pin the link to persist it beyond process lifetime
	linkPath := filepath.Join(o.GetBpfBaseDir(), fmt.Sprintf("link_%s", ifaceName))
	if err := l.Pin(linkPath); err != nil {
		l.Close()
		return nil, fmt.Errorf("failed to pin link: %w", err)
	}

	return &AttachedProgram{
		Program:   loaded,
		Interface: ifaceName,
		Link:      l,
	}, nil
}

// DetachFromInterface detaches a program from an interface.
func (o *Ouroboros) DetachFromInterface(attached *AttachedProgram) error {
	if attached == nil || attached.Link == nil {
		return fmt.Errorf("invalid attached program")
	}

	// Unpin the link first
	linkPath := filepath.Join(o.GetBpfBaseDir(), fmt.Sprintf("link_%s", attached.Interface))
	if err := attached.Link.Unpin(); err != nil {
		// Continue with close even if unpin fails
		_ = attached.Link.Close()
		return fmt.Errorf("failed to unpin link: %w", err)
	}

	// Close the link to detach from interface
	if err := attached.Link.Close(); err != nil {
		return fmt.Errorf("failed to close link: %w", err)
	}

	// Remove the pinned file if it still exists
	_ = os.Remove(linkPath)

	return nil
}

// DetachByName detaches a program from an interface by name.
// This is useful when you don't have the AttachedProgram handle.
// This method loads the pinned link and uses it to detach.
func (o *Ouroboros) DetachByName(ifaceName string) error {
	_, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}

	// Load the pinned link
	linkPath := filepath.Join(o.GetBpfBaseDir(), fmt.Sprintf("link_%s", ifaceName))
	if _, err := os.Stat(linkPath); os.IsNotExist(err) {
		return fmt.Errorf("no pinned link found for interface %s", ifaceName)
	}

	l, err := link.LoadPinnedLink(linkPath, nil)
	if err != nil {
		return fmt.Errorf("failed to load pinned link: %w", err)
	}

	// Unpin and close
	if err := l.Unpin(); err != nil {
		_ = l.Close()
		return fmt.Errorf("failed to unpin link: %w", err)
	}

	if err := l.Close(); err != nil {
		return fmt.Errorf("failed to close link: %w", err)
	}

	// Clean up the pinned file
	_ = os.Remove(linkPath)

	return nil
}

// IsAttached checks if any XDP program is attached to an interface.
// This checks for a pinned link in the BPF filesystem.
func (o *Ouroboros) IsAttached(ifaceName string) (bool, error) {
	_, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return false, fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}

	// Check if a pinned link exists for this interface
	linkPath := filepath.Join(o.GetBpfBaseDir(), fmt.Sprintf("link_%s", ifaceName))
	_, err = os.Stat(linkPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to check link: %w", err)
	}

	return true, nil
}

// GetAttachedProgramID returns the ID of the program attached to an interface.
// Returns 0 if no program is attached.
// Note: This requires additional kernel support and is currently not fully implemented.
func (o *Ouroboros) GetAttachedProgramID(ifaceName string) (uint32, error) {
	// This would require netlink or bpftool integration to properly query
	return 0, fmt.Errorf("not implemented: requires netlink support")
}

// ListInterfaces returns all available network interfaces.
func (o *Ouroboros) ListInterfaces() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	names := make([]string, len(ifaces))
	for i, iface := range ifaces {
		names[i] = iface.Name
	}

	return names, nil
}

// AttachMainProgram is a convenience method to attach the main program to an interface.
// This loads ALL programs in the project (to populate the program map for tail calls)
// and then attaches the main program to the specified interface.
func (o *Ouroboros) AttachMainProgram(ifaceName string, opts *AttachOptions) (*AttachedProgram, error) {
	mainProg := o.GetMainProgram()
	if mainProg == nil {
		return nil, fmt.Errorf("no main program configured")
	}

	// Load ALL programs to populate the program map for tail calls
	// This is necessary because XDP programs may use tail calls to other programs
	loadedProgs, loadErrors := o.LoadAllPrograms(nil)

	// Check if main program loaded successfully
	loaded, ok := loadedProgs[mainProg.Name]
	if !ok {
		if err, hasErr := loadErrors[mainProg.Name]; hasErr {
			return nil, fmt.Errorf("failed to load main program: %w", err)
		}
		return nil, fmt.Errorf("main program %s not loaded", mainProg.Name)
	}

	// Log any errors loading other programs (non-fatal)
	for name, err := range loadErrors {
		if err != nil && name != mainProg.Name {
			logger.Warn("Failed to load program (tail calls to this program may fail)",
				"program", name, "error", err)
		}
	}

	return o.AttachToInterface(loaded, ifaceName, opts)
}
