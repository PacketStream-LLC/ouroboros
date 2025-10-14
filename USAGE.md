# Usage
## Build Flows
If you are using git, The `_ouroboros/` directory is automatically generated and should be ignored in your `.gitignore` file.,  
This is intended to be a generated directory, so you don't need to check it into version control.  

If you have cloned a repository that uses `ouroboros`, you can generate the `_ouroboros/` directory by running:  
```bash
ouroboros generate
```

## Commands
| Command | Description |
| --- | --- |
| `ouroboros create` | Create a new ouroboros project in current directory |
| `ouroboros add <name>` | Add a new eBPF program to your project. |
| `ouroboros build` | Compile all eBPF programs in the project. |
| `ouroboros load` | Load the compiled eBPF programs into the kernel. |
| `ouroboros unload` | Unload the compiled eBPF programs from the kernel and unpin maps. |
| `ouroboros reload` | Unload and then load the eBPF programs and maps. |
| `ouroboros attach <interface>` | Attach eBPF programs to a specified interface. |
| `ouroboros detach <interface>` | Detach eBPF programs from a specified interface. |
| `ouroboros run <interface>` | Build, load, attach, and show log at the same time. |
| `ouroboros log` | Attach to kernel tracing for debugging ebpf_printk. |
| `ouroboros generate` | Generate _ouroboros related files (e.g., headers, maps) |
| `ouroboros map` | List all eBPF maps discovered in compiled programs with their specifications. |
| `ouroboros flow [output_file]` | Analyze the tail call flow and generate a Mermaid flowchart. |

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
  "shared_maps": [
    {
      "name": "events",
      "type": "RingBuf",
      "max_entries": 65536
    }
  ],
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
- **`shared_maps`**: A list of eBPF maps that are shared between all the programs.
  - `name`: The name of the map.
  - `type`: The type of the map (e.g., `RingBuf`, `Hash`, `Array`).
  - `max_entries`: The maximum number of entries in the map.
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

## Map Discovery

The `ouroboros map` command analyzes compiled eBPF programs and lists all discovered maps with their specifications:

```bash
ouroboros map
```

This command:
- Parses compiled `.o` files from the `target/` directory
- Extracts map metadata (type, key size, value size, max entries)
- Shows which programs use each map
- Identifies potential shared maps (used in multiple programs or prefixed with `shared_`)

Example output:
```
Maps discovered in compiled programs:

📍 events
   Type:        RingBuf
   Key Size:    0 bytes
   Value Size:  0 bytes
   Max Entries: 65536
   Program:     main

📍 shared_config
   Type:        Hash
   Key Size:    4 bytes
   Value Size:  64 bytes
   Max Entries: 1024
   Programs:    main, filter, process

Total: 2 map(s) discovered

Potential shared maps (1):
  - shared_config (used in: main, filter, process)
```

Use `--verbose` flag for more detailed information:
```bash
ouroboros map -v
```

## Flowchart Generation

The `ouroboros flow` command analyzes your eBPF programs and generates a [Mermaid](https://mermaid-js.github.io/mermaid/#/) flowchart of the tail call flow.

```bash
ouroboros flow
```

This will create a `flow.mermaid` file in the current directory. You can then use a Mermaid viewer to see the flowchart.

