<p align="center"><img width="384" height="384" alt="ouroboros logo" src="https://github.com/user-attachments/assets/8484c64e-1058-40ca-8e12-1b6d4d713594" /></p>

> [!WARNING]
> This is not an official PacketStream LLC service or product.
>
> This is still in experimental state and subject to change until v1.0.0 has reached:
> * **CLI**: less-likely to change.
> * **SDK**: Rapid development in progress and implementing QoL changes right now (v0.1.x)
>
> Use at your own risk.

`ouroboros` helps you manage and chain multiple eBPF programs together via managing central `PROGRAM_MAPS` and shared `PINNED` eBPF maps/ringbufs, 
making it easier to `bpf_tail_call` and build complex chain of eBPF program flow structure for complext programs

## What is it?

Running a single eBPF program is straightforward. But what if you need to run many of them in a specific order? `ouroboros` simplifies this by letting you:

- **Organize** your eBPF programs into a single project with metadata provided with `ouroboros.json`.
- **Share** and **Allocate** eBPF maps and ring buffers on initialization via `ouroboros.json` configuration.
- **Create** program maps for centralized tail call management and easy chaining in your C code.
- **Machine Generated** constants for program IDs and jump targets, so you don't have to manually manage them.
- **Chain** them together using eBPF tail calls with generated `JUMP_TO_PROGRAM` and `PROG_*` constants, easily implement tailing to next program.
- **Build and load** everything with simple commands, without finding pinned path when you use `bpftool` directly.

## Installation

Make sure you have Go, Clang, and LLVM installed.

```bash
go install github.com/PacketStream-LLC/ouroboros@latest
```

## Getting Started

1.  **Create a project:**
    ```bash
    mkdir my_firewall
    cd my_firewall
    ouroboros create
    ```
    This will create `ouroboros.json`, `src/` and `target/` directories.

2.  **Add your first program:**
    ```bash
    ouroboros add block_list
    ```
    Now, edit the C code in `src/block_list/main.c`.

3.  **Build and load it:**
    ```bash
    ouroboros load
    ```
    This will compile your programs and load them into the kernel.

4.  **Attach to an interface:**
    ```bash
    ouroboros attach eth0
    ```

5.  **See the logs:**
    ```bash
    ouroboros log
    ```

## Usage
See [USAGE.md](USAGE.md) for detailed usage instructions.
