# Usage
## Build Flows
If you are using git, The `_ouroboros/` directory is automatically generated and should be ignored in your `.gitignore` file.,  
This is intended to be a generated directory, so you don't need to check it into version control.  

If you have cloned a repository that uses `ouroboros`, you can generate the `_ouroboros/` directory by running:  
```bash
ouroboros generate
```

## Commands

### Project Management
| Command | Description |
| --- | --- |
| `ouroboros create` | Create a new ouroboros project in current directory |
| `ouroboros add <name>` | Add a new eBPF program to your project |
| `ouroboros generate` | Generate _ouroboros related files (e.g., headers, maps) |
| `ouroboros clean` | Remove all build artifacts and temporary files |

### Build & Deploy
| Command | Description |
| --- | --- |
| `ouroboros build` | Compile all eBPF programs in the project |
| `ouroboros load` | Load the compiled eBPF programs into the kernel |
| `ouroboros unload` | Unload the compiled eBPF programs from the kernel and unpin maps |
| `ouroboros reload` | Unload and then load the eBPF programs and maps |
| `ouroboros attach <interface>` | Attach eBPF programs to a specified interface (with persistent pinned link) |
| `ouroboros detach <interface>` | Detach eBPF programs from a specified interface |
| `ouroboros run <interface>` | Build, load, attach, and show log at the same time |

### Map Operations
| Command | Description |
| --- | --- |
| `ouroboros map list` | List all eBPF maps discovered in compiled programs |
| `ouroboros map list --type=<type>` | Filter maps by type (hash, array, ringbuf, etc.) |
| `ouroboros map show [name\|id]` | Show details of a specific map |
| `ouroboros map flow [map-name]` | Generate Mermaid diagram showing program dependencies for maps |
| `ouroboros map log <name>` | Read and print ringbuf events from a map (raw output) |
| `ouroboros map dump <name>` | Dump map contents (pass-through to bpftool) |
| `ouroboros map update <name> ...` | Update map entry (pass-through to bpftool) |
| `ouroboros map lookup <name> ...` | Lookup map entry (pass-through to bpftool) |
| `ouroboros map delete <name> ...` | Delete map entry (pass-through to bpftool) |
| `ouroboros map getnext <name> ...` | Get next map key (pass-through to bpftool) |

### Analysis & Debugging
| Command | Description |
| --- | --- |
| `ouroboros log` | Attach to kernel tracing for debugging bpf_trace_printk |
| `ouroboros flow [output_file]` | Analyze the tail call flow and generate a Mermaid flowchart |

## `ouroboros.json`

The `ouroboros.json` file is the heart of your project. It defines the programs, shared maps, and other settings.

```json
{
  "programs": [
    {
      "name": "main",
      "id": 1,
      "is_main": true
    }
  ],
  "program_map": "ouroboros_programs",
  "program_prefix": "ouroboros_",
  "compile_args": [
    "-Wall"
  ]
}
```

- **`programs`**: A list of all the eBPF programs in your project.
  - `name`: The name of the program (must match the directory name in `src/`).
  - `id`: A unique ID for the program. This is used for tail calls.
  - `is_main`:  Indicates which program is the entry point.
- **`program_map`**: The name of the eBPF map that holds the program array for tail calls.
- **`program_prefix`**: A prefix for all the programs when they are loaded into the kernel.
- **`compile_args`**: A list of arguments to pass to `clang` when compiling the programs.

## `_global` directory
You can create a `_global` directory inside `src/` to hold shared code and headers that can be included in all your eBPF programs.

For example,
```c
#include "_global/common.h"
```

## Generated Constants

`ouroboros` generates a header file at `src/_ouroboros/programs.h` with constants that you can use in your eBPF programs.

By default, it generates Program IDs as you defined on `ouroboros.json`, and a helper macro for tail calls.

For example, if you have a program named `block_list` with ID `2`, it will generate:  
```c
#define PROG_block_list 2
```

It also generates a macro for tail calls:  
```c
#define JUMP_TO_PROGRAM(ctx, program_id) ...
```

So, if you want to jump to the `block_list` program, you can do:  
```c
JUMP_TO_PROGRAM(ctx, PROG_block_list);
```

This makes it easy to tail call other programs without having to hardcode program IDs, and No need to manually manage the program map.  
By default if you are using `ouroboros build` command to build, you can include this file in your C code like this:  
```c
#include "_ouroboros/programs.h"
```  

## Generated "Shared Maps" Header
`ouroboros` also generates a header file at `src/_ouroboros/maps.h` with definitions for your shared maps.  
This is automatically machine generated and can be imported via `src/_ouroboros/maps.h` in your C code, so you don't need to keep track of which maps are available by looking at `/sys/fs/bpf/` or `bpftool` output.

## Map Operations

### Map Discovery and Listing

The `ouroboros map list` command analyzes compiled eBPF programs and lists all discovered maps in bpftool-compatible format:

```bash
ouroboros map list
```

Example output (matches `bpftool map` format):
```
20: prog_array  name hs_programs  flags 0x0
    key 4B  value 4B  max_entries 65535  memlock 524544B
21: hash  name global_bucket_s  flags 0x0
    key 16B  value 8B  max_entries 10000000  memlock 988438528B
23: ringbuf  name global_session_  flags 0x0
    key 0B  value 0B  max_entries 4096  memlock 16680B
```

**Filter by map type:**
```bash
ouroboros map list --type=hash      # List only hash maps
ouroboros map list --type=ringbuf   # List only ringbuf maps
ouroboros map list -t array         # Short flag version
```

**Show program information:**
```bash
ouroboros map list --verbose        # Show which programs use each map
ouroboros map list -v               # Short flag version
```

### Map Inspection

**Show detailed map information:**
```bash
ouroboros map show mc_sessions
```

**Generate map dependency diagram:**
```bash
ouroboros map flow                  # All maps
ouroboros map flow test_sessions     # Specific map
```

### Real-time Map Monitoring

**Monitor ringbuf events (raw output):**
```bash
ouroboros map log json_ringbuf              # Print raw bytes to stdout
ouroboros map log json_ringbuf | jq .       # Parse as JSON
ouroboros map log json_ringbuf > events.log # Save to file
```

### Map Manipulation (bpftool pass-through)

All standard bpftool map operations work with automatic map name resolution (requires `bpftool` to be installed on host):

```bash
# Dump map contents
ouroboros map dump sessions
ouroboros map dump sessions --json --pretty

# Update map entry
ouroboros map update sessions key hex 0x12 0x34 value hex 0x56 0x78

# Lookup map entry
ouroboros map lookup sessions key hex 0x12 0x34

# Delete map entry
ouroboros map delete sessions key hex 0x12 0x34

# Get next key
ouroboros map getnext sessions key hex 0x12 0x34
```

**How it works:**
- Map names are automatically resolved to pinned paths
- `ouroboros map dump sessions` → `bpftool map dump pinned /sys/fs/bpf/sessions`
  (Supposing `/sys/fs/bpf` was set for the bpfPath)
- All flags and arguments are passed through to bpftool

## Attaching Programs to Interfaces

The `attach` and `detach` commands manage XDP program attachments to network interfaces with persistent pinned links.

### Attach Program
```bash
sudo ouroboros attach eth0
# Output:
# Successfully attached program to interface eth0
# Link pinned at: /sys/fs/bpf/link_main_eth0
```

**Features:**
- Creates a persistent pinned link at `/sys/fs/bpf/link_{program}_{interface}`
- Attachment survives command exit and persists in the kernel
- Link file enables proper cleanup with detach command

### Detach Program
```bash
sudo ouroboros detach eth0
# Output:
# Successfully detached program from interface eth0 (via pinned link)
```

**Fallback mechanism:**
- First tries to use pinned link (preferred method)
- Falls back to netlink if no pinned link exists
- Works with programs attached by other tools or manually

**Example workflow:**
```bash
# Clean slate
sudo ouroboros detach eth0

# Build and attach
sudo ouroboros build
sudo ouroboros load
sudo ouroboros attach eth0

# Program stays attached even after terminal closes
# Verify with: ip link show eth0

# Later, clean up
sudo ouroboros detach eth0
sudo ouroboros unload
```

## Cleaning Build Artifacts

Remove all build artifacts and temporary files:

```bash
ouroboros clean
```

This removes:
- `target/` directory (all compiled `.o` files, `.ll` files, `.merged.o` files)
- Any stray build artifacts in the project root

## Flowchart Generation

The `ouroboros flow` command analyzes your eBPF programs and generates a [Mermaid](https://mermaid-js.github.io/mermaid/#/) flowchart of the tail call flow.

```bash
ouroboros flow
```

This will create a `flow.mermaid` file in the current directory. You can then use a Mermaid viewer to see the flowchart.

