package ouroboros

import (
	"fmt"
	"net"

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

	return attached.Link.Close()
}

// DetachByName detaches a program from an interface by name.
// This is useful when you don't have the AttachedProgram handle.
func (o *Ouroboros) DetachByName(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}

	// Attach with nil program to detach
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   nil,
		Interface: iface.Index,
	})
	if err != nil {
		return err
	}
	if l != nil {
		return l.Close()
	}
	return nil
}

// IsAttached checks if any XDP program is attached to an interface.
// Note: This is a simplified implementation that attempts to attach a nil program.
// A more robust implementation would require kernel support for querying attached programs.
func (o *Ouroboros) IsAttached(ifaceName string) (bool, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return false, fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}

	// Try to attach with replace flag - if there's a program, it will fail
	_, err = link.AttachXDP(link.XDPOptions{
		Interface: iface.Index,
		Flags:     link.XDPDriverMode,
	})

	// If attach fails, there might be an existing program
	return err != nil, nil
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
func (o *Ouroboros) AttachMainProgram(ifaceName string, opts *AttachOptions) (*AttachedProgram, error) {
	mainProg := o.GetMainProgram()
	if mainProg == nil {
		return nil, fmt.Errorf("no main program configured")
	}

	// Load the program if not already loaded
	var loaded *LoadedProgram
	var err error

	if o.IsProgramLoaded(mainProg.Name) {
		// Get existing loaded program
		prog, err := o.GetLoadedProgram(mainProg.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to get loaded program: %w", err)
		}

		loaded = &LoadedProgram{
			Name:    mainProg.Name,
			ID:      mainProg.ID,
			Program: prog,
		}
	} else {
		// Load the program
		loaded, err = o.LoadProgram(mainProg.Name, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to load program: %w", err)
		}
	}

	return o.AttachToInterface(loaded, ifaceName, opts)
}
