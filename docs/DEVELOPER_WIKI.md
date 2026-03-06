# ONCRIX Developer Wiki

Comprehensive guide for ONCRIX kernel development.

## Architecture Overview

ONCRIX uses a **microkernel architecture** where only the most essential services
run in kernel space (Ring 0). All other OS services — device drivers, file systems,
networking — run as isolated user-space processes that communicate via IPC.

### Layer Diagram

```
User Space (Ring 3)
├── Applications (POSIX-compatible)
├── System Services (VFS, networking, etc.)
├── Device Drivers (user-space)
└── Syscall Interface
────────────────────────────────
Kernel Space (Ring 0)
├── Scheduler
├── IPC (message passing)
├── Memory Management (page tables, physical allocator)
└── HAL (interrupt routing, timer, architecture-specific)
```

### Design Principles

1. **Minimal kernel**: Only scheduling, IPC, and memory management in Ring 0
2. **Message passing**: All service communication through typed IPC messages
3. **Capability-based security**: Access rights are unforgeable tokens
4. **Fault isolation**: A crashed driver doesn't crash the system
5. **POSIX at the edge**: POSIX compatibility implemented in user-space libraries

## Crate-by-Crate Guide

### oncrix-lib
**Role**: Foundational types shared across all crates.
- `Error` enum — top-level error type
- `Result<T>` type alias
- Common constants and utility functions

### oncrix-hal
**Role**: Hardware Abstraction Layer — isolates architecture-specific code.
- CPU initialization, privilege levels
- Interrupt controller (APIC/GIC) abstraction
- Timer abstraction (PIT/HPET/APIC timer / ARM generic timer)
- Serial port / UART
- Architecture-gated modules: `#[cfg(target_arch = "x86_64")]`, `#[cfg(target_arch = "aarch64")]`, `#[cfg(target_arch = "riscv64")]`

### oncrix-bootloader
**Role**: Early boot and kernel handoff.
- UEFI / Multiboot2 protocol support
- Memory map parsing
- Kernel ELF loading
- Initial page table setup
- Serial console for early debug output

### oncrix-mm
**Role**: Memory management subsystem.
- Physical page allocator (bitmap / buddy allocator)
- Virtual memory manager (page table manipulation)
- Kernel heap allocator (slab / bump allocator)
- Address space management per process
- Key types: `PhysAddr`, `VirtAddr`, `PageTable`, `Frame`, `Page`

### oncrix-ipc
**Role**: Inter-Process Communication — the backbone of the microkernel.
- Synchronous IPC: `send()`, `receive()`, `reply()`
- Asynchronous notifications
- Shared memory regions
- Capability-based endpoint management
- Message format: fixed header + variable payload

### oncrix-process
**Role**: Process and thread lifecycle.
- Process creation / destruction
- Thread management
- Scheduler (priority-based preemptive)
- Context switching
- Key types: `Process`, `Thread`, `Pid`, `Tid`, `SchedulerState`

### oncrix-vfs
**Role**: Virtual File System abstraction.
- Unified file operations across different file systems
- Mount table management
- Path resolution (namei)
- File descriptor table
- POSIX file semantics (open, read, write, close, seek, stat)

### oncrix-drivers
**Role**: User-space device driver framework.
- Driver registration and discovery
- Device tree / ACPI abstraction
- Common driver interfaces (block, char, network)
- DMA buffer management
- Interrupt forwarding from kernel to user-space drivers

### oncrix-syscall
**Role**: POSIX-compatible system call interface.
- Syscall ABI definition (register conventions)
- Argument validation and sanitization
- Syscall dispatch table
- User-space pointer validation
- POSIX errno mapping

### oncrix-kernel
**Role**: Microkernel integration crate — ties everything together.
- Kernel entry point (`_start`)
- Initialization sequence
- Panic handler
- Global state management

## Error Handling Patterns

All fallible operations return `oncrix_lib::Result<T>`:

```rust
use oncrix_lib::{Error, Result};

pub fn allocate_page() -> Result<PhysAddr> {
    let frame = frame_allocator
        .allocate()
        .ok_or(Error::OutOfMemory)?;
    Ok(frame.start_address())
}
```

## Testing Strategy

- **Unit tests**: Per-module `#[cfg(test)]` blocks
- **Integration tests**: Cross-crate tests in `tests/` directories
- **Architecture tests**: Conditional compilation `#[cfg(target_arch = "...")]`
- **QEMU tests**: Full-system boot tests using QEMU runner

## Build & CI

### Requirements
- Rust 1.85+ (nightly for `#![no_std]` features)
- QEMU 7.0+ (for system testing)
- `rust-src` component (for `#![no_std]` cross-compilation)

### CI Pipeline
```bash
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo build --workspace
```

## Glossary

| Term | Definition |
|------|-----------|
| **IPC** | Inter-Process Communication — message passing between processes |
| **TCB** | Trusted Computing Base — the minimal set of code that must be correct for security |
| **HAL** | Hardware Abstraction Layer — platform-independent hardware interface |
| **VFS** | Virtual File System — unified file system abstraction |
| **MMU** | Memory Management Unit — hardware for virtual-to-physical address translation |
| **TLB** | Translation Lookaside Buffer — MMU cache for page table entries |
| **GDT** | Global Descriptor Table — x86 segment descriptor table |
| **IDT** | Interrupt Descriptor Table — x86 interrupt handler registration |
| **APIC** | Advanced Programmable Interrupt Controller — x86 interrupt hardware |
| **UEFI** | Unified Extensible Firmware Interface — modern boot protocol |
| **ELF** | Executable and Linkable Format — standard executable format |
| **DMA** | Direct Memory Access — hardware-initiated memory transfers |
| **POSIX** | Portable Operating System Interface — Unix API standard |
| **Capability** | Unforgeable token granting specific access rights to a resource |
