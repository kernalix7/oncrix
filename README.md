# ONCRIX

**English** | [한국어](docs/README.ko.md)

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

> **[Architecture deep-dive →](docs/ARCHITECTURE.md)** — design philosophy, OS comparison, security model, POSIX strategy

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

### Boot in QEMU

```bash
bash scripts/run-qemu.sh
```

Expected output (10-phase boot sequence):

```
[ONCRIX] Kernel booting...
[ONCRIX] Serial console initialized (COM1, 115200 8N1)
[ONCRIX] GDT initialized
[ONCRIX] IDT initialized (5 exception handlers)
[ONCRIX] Kernel heap initialized (16 MiB)
[ONCRIX] Scheduler initialized (idle thread ready)
[ONCRIX] SYSCALL/SYSRET initialized
[ONCRIX] PIC initialized, PIT running at ~100 Hz
[ONCRIX] All early initialization complete.
[ONCRIX] Mounting root filesystem...
[ONCRIX] Root filesystem mounted (ramfs on /)
[ONCRIX] Created /dev /proc /tmp /sbin
[ONCRIX] Initializing IPC channels...
[ONCRIX] IPC channels ready (kernel<->console, kernel<->devmgr, kernel<->netd)
[ONCRIX] Starting service manager...
[ONCRIX] Service manager boot complete
[ONCRIX] Entering halt loop.
```

### Verify

```bash
cargo fmt --all -- --check && cargo clippy --workspace -- -D warnings && cargo build --workspace
```

## Roadmap

### Phase 1: Foundation
- [x] Project structure and workspace setup (10-crate workspace, CI/CD)
- [x] Boot entry via Xen PVH ELF Note (QEMU `-kernel`) + Multiboot2 header (GRUB)
- [x] 32-bit → 64-bit long-mode transition (boot.S stub at 1 MiB physical)
- [x] Serial console output (UART 16550, COM1 115200 8N1)
- [x] Physical memory manager (bitmap allocator, 128 MiB)
- [x] Virtual memory (4-level page tables, map/unmap, TLB flush)
- [x] Kernel heap allocator (linked-list free-list, 16 MiB)
- [x] GDT/IDT (5 segments + TSS, 256 vectors, 5 exception handlers)
- [x] Linker script (higher-half at 0xFFFFFFFF80000000)
- [x] QEMU integration script (boots all 10 init phases)

### Phase 2: Core Kernel
- [x] 8259 PIC driver (IRQ remap to vectors 32-47)
- [x] PIT timer (~100 Hz periodic)
- [x] Local APIC timer driver (MMIO, calibration, one-shot/periodic)
- [x] ACPI table parsing (RSDP, XSDT, MADT)
- [x] Round-robin scheduler (256 threads)
- [x] Context switching (callee-saved register save/restore)
- [x] Preemptive scheduling (priority-based time slices)
- [x] Kernel thread pool (32 threads, 8 KiB stacks)
- [x] SYSCALL/SYSRET entry point (MSR setup, assembly stub)
- [x] Ring 0 to Ring 3 transition (iretq)

### Phase 3: IPC & Process
- [x] Synchronous IPC channels (ring buffer, 16 messages)
- [x] Channel registry (64 channels)
- [x] Process/Thread structs with PID/TID newtypes
- [x] ELF64 binary loader (header validation, PT_LOAD segments)
- [x] User-space process execution (exec, address space setup)
- [x] fork implementation (CoW tracker, reference counting)
- [x] Per-process virtual address space (64 VmRegions)
- [x] User pointer validation (copy_from_user/copy_to_user)

### Phase 4: Services
- [x] VFS layer (inode, dentry cache, superblock, mount table)
- [x] ramfs (128 inodes, 4 KiB files, full InodeOps)
- [x] devfs (64 device nodes, char/block registration)
- [x] procfs (version, uptime, meminfo, cpuinfo)
- [x] Pipe (4 KiB ring buffer, 64 pipes)
- [x] Path resolution and VFS open (O_CREAT/O_TRUNC)
- [x] VFS operations (read, write, lseek, stat)
- [x] Device driver framework (Driver trait, registry, 64 devices)

### Phase 5: POSIX Compatibility
- [x] POSIX syscall numbers (Linux x86_64 ABI)
- [x] Syscall dispatcher + 200+ handler stubs (io_uring, BPF, perf, prctl, landlock, pidfd)
- [x] Signal handling (32 signals, mask, pending)
- [x] File descriptor table (256 fds, dup2)
- [x] stat/fstat/lseek/pipe/dup2 handlers
- [x] SYSCALL/SYSRET fast-path entry (MSR setup)
- [ ] Ring 0 → Ring 3 transition (in progress)
- [ ] execve syscall end-to-end
- [ ] Basic shell

### Phase 6: Multi-arch (in progress)
- [x] x86_64 (primary, boots in QEMU)
- [ ] aarch64 (HAL boot stub in progress)
- [ ] riscv64 (HAL boot stub planned)

### Phase 7-9: Userspace, Testing, Docs (in progress)
- [ ] `crates/userspace/` tree (init, sh, libc shim)
- [ ] QEMU integration tests in CI
- [x] Architecture documentation (x86_64 boot flow)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

```
Copyright 2026 ONCRIX Contributors
SPDX-License-Identifier: Apache-2.0
```
