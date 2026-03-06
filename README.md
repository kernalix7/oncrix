# ONCRIX

[한국어](docs/README.ko.md)

**ONCRIX is Not a Copy, Real Independent uniX**

ONCRIX is a new operating system built from the ground up with a **microkernel architecture**,
designed as an independent Unix-like OS with full POSIX compatibility.
Written entirely in **Rust** for memory safety, security, and performance.

## Why ONCRIX?

Traditional monolithic kernels pack everything — drivers, file systems, networking — into a single
privileged address space. A single bug in any component can crash the entire system.

ONCRIX takes a different approach:

- **Microkernel design**: Only scheduling, IPC, and basic memory management run in kernel space
- **Fault isolation**: Drivers and services run as user-space processes; a crashed driver doesn't bring down the system
- **Capability-based security**: Fine-grained access control at the IPC level
- **POSIX compatibility**: Run existing Unix applications without modification

## Core Design Goals

| Goal | Approach |
|------|----------|
| **Stability** | Rust's ownership model eliminates data races and memory corruption. Graceful error propagation via `Result<T, E>` throughout the kernel |
| **Security** | Capability-based access control, privilege separation, minimal trusted computing base (TCB) |
| **Extensibility** | Modular microkernel — add or replace OS services without rebooting. User-space drivers and file systems |
| **Performance** | Zero-cost abstractions, lock-free data structures, efficient synchronous/asynchronous IPC, minimal context switches |

## Architecture

```
┌───────────────────────────────────────────────────────┐
│                  User Applications                    │
│                (POSIX-compatible API)                  │
├──────────────┬─────────┬────────────┬─────────────────┤
│    Syscall   │   VFS   │  Drivers   │    Services     │
│(oncrix-      │(oncrix- │(oncrix-    │                 │
│  syscall)    │  vfs)   │  drivers)  │                 │
├──────────────┴─────────┴────────────┴─────────────────┤
│                  IPC (oncrix-ipc)                      │
│           Message Passing & Shared Memory              │
├──────────────┬────────────────────────┬───────────────┤
│   Process    │   Memory Management    │      HAL      │
│(oncrix-      │     (oncrix-mm)        │  (oncrix-hal) │
│  process)    │                        │               │
├──────────────┴────────────────────────┴───────────────┤
│             Microkernel (oncrix-kernel)                │
│         Scheduler · Core IPC · Page Tables             │
├───────────────────────────────────────────────────────┤
│            Bootloader (oncrix-bootloader)              │
└───────────────────────────────────────────────────────┘
                        Hardware
```

## Project Structure

```
oncrix/
├── crates/
│   ├── kernel/          # Microkernel core (scheduler, IPC, memory management)
│   ├── hal/             # Hardware Abstraction Layer (x86_64, aarch64, riscv64)
│   ├── bootloader/      # Boot protocol and early initialization
│   ├── drivers/         # User-space device driver framework
│   ├── vfs/             # Virtual File System
│   ├── process/         # Process and thread management
│   ├── ipc/             # Inter-Process Communication primitives
│   ├── mm/              # Memory management (virtual memory, page allocator)
│   ├── syscall/         # POSIX-compatible system call interface
│   └── lib/             # Shared utilities and error types
├── docs/                # Documentation and developer wiki
├── .github/             # CI/CD workflows and issue templates
├── Cargo.toml           # Workspace configuration
├── CONTRIBUTING.md      # Contribution guidelines
├── CHANGELOG.md         # Version history
├── SECURITY.md          # Security policy
├── CODE_OF_CONDUCT.md   # Community standards
├── LICENSE              # Apache License 2.0
└── README.md
```

## Crate Dependency Graph

```
                    ┌──────────┐
                    │  kernel  │
                    └────┬─────┘
           ┌─────┬──────┼──────┬─────────┐
           v     v      v      v         v
       ┌──────┐┌───┐┌──────┐┌─────┐┌────────┐
       │syscall││ipc││  mm  ││proc ││  hal   │
       └──┬───┘└─┬──┘└──┬───┘└──┬──┘└────────┘
          │      │      │       │
          v      v      v       v
       ┌──────┐  │   ┌─────┐   │
       │ vfs  │  │   │ hal │   │
       └──┬───┘  │   └─────┘   │
          │      │              │
          v      v              v
       ┌─────────────────────────────┐
       │            lib              │
       └─────────────────────────────┘
```

## Tech Stack

- **Language**: Rust 1.85+ (Edition 2024)
- **Build System**: Cargo workspace
- **Target Architectures**: x86_64 (primary), aarch64 (planned), riscv64 (planned)
- **License**: Apache-2.0
- **CI/CD**: GitHub Actions

## Getting Started

### Prerequisites

- Rust 1.85+ (nightly recommended for `#![no_std]` kernel development)
- QEMU (for testing the OS in a virtual machine)

### Build

```bash
cargo build --workspace
```

### Verify

```bash
cargo fmt --all -- --check && cargo clippy --workspace -- -D warnings && cargo build --workspace
```

## Roadmap

### Phase 1: Foundation
- [x] Project structure and workspace setup
- [ ] Basic bootloader (UEFI/Multiboot2)
- [ ] Serial console output
- [ ] Physical memory manager (bitmap allocator)
- [ ] Virtual memory (page tables)

### Phase 2: Core Kernel
- [ ] Kernel heap allocator
- [ ] Interrupt handling (IDT, APIC)
- [ ] Timer (PIT/HPET/APIC timer)
- [ ] Basic scheduler (round-robin)
- [ ] Context switching

### Phase 3: IPC & Process
- [ ] Synchronous IPC (send/receive/reply)
- [ ] Asynchronous IPC (notifications)
- [ ] Process creation and destruction
- [ ] ELF loader
- [ ] User-space execution

### Phase 4: Services
- [ ] VFS layer
- [ ] RAM disk file system
- [ ] Device driver framework
- [ ] Console driver
- [ ] Keyboard/mouse driver

### Phase 5: POSIX Compatibility
- [ ] POSIX system call layer
- [ ] Signal handling
- [ ] Pipe and FIFO
- [ ] fork/exec/wait
- [ ] Basic shell

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

```
Copyright 2026 ONCRIX Contributors
SPDX-License-Identifier: Apache-2.0
```
