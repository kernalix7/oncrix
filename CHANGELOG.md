# Changelog

**English** | [한국어](docs/CHANGELOG.ko.md)

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

#### Project Infrastructure
- 10-crate Cargo workspace (kernel, hal, bootloader, mm, ipc, process, syscall, vfs, drivers, lib)
- CI/CD pipeline with GitHub Actions (fmt, clippy, build)
- Developer documentation, wiki, and verification checklist
- Community files (CONTRIBUTING, CODE_OF_CONDUCT, SECURITY)
- English and Korean documentation
- QEMU integration script and higher-half linker script

#### oncrix-lib
- `Error` enum (10 variants), `Result<T>` type alias, `Display` impl

#### oncrix-hal
- `SerialPort`, `InterruptController`, `Timer` traits
- x86_64: UART 16550, GDT (5 segments + TSS), IDT (256 vectors)
- x86_64: 8259 PIC (IRQ remap 32-47), PIT timer (~100 Hz)
- x86_64: Local APIC timer (MMIO, PIT calibration, periodic/one-shot)
- x86_64: shared port I/O (`inb`/`outb`)
- ACPI parsing (RSDP v1/v2, XSDT, MADT — Local APIC/IO APIC/Override)

#### oncrix-bootloader
- `BootInfo`, `MemoryMap`, Multiboot2 header

#### oncrix-mm
- `PhysAddr`/`VirtAddr` newtypes, `Frame`/`Page`, `FrameAllocator` trait
- Bitmap frame allocator (128 MiB), 4-level page tables, TLB flush
- Kernel heap (`LinkedListAllocator`, 256 KiB), `map_page`/`unmap_page`
- Per-process `AddressSpace` (64 VmRegions, overlap detection)

#### oncrix-ipc
- `Message` (header + 256-byte payload), `EndpointId`, `SyncIpc` trait
- `Channel` ring buffer (16 messages), `ChannelRegistry` (64 channels)

#### oncrix-process
- `Pid`/`Tid` newtypes, `Process` (64 threads), `Thread`, `Priority`
- Round-robin scheduler (256 threads), POSIX signal handling (32 signals)
- `fork_process()` with `CowTracker` (CoW reference counting)

#### oncrix-vfs
- Inode, dentry cache (256 entries), superblock, mount table (16 mounts)
- `FdTable` (256 fds, dup2), ramfs (128 inodes, 4 KiB files)
- devfs (64 nodes), procfs (version/uptime/meminfo/cpuinfo)
- Pipe (4 KiB ring buffer, 64 pipes, EOF/EPIPE)
- Path resolution (`resolve_path`, `vfs_open` with O_CREAT/O_TRUNC)
- VFS operations (`vfs_read`, `vfs_write`, `vfs_lseek`, `vfs_stat`)

#### oncrix-syscall
- POSIX syscall numbers (Linux x86_64 ABI), dispatcher, 22 handlers
- `StatBuf` repr(C), `error_to_errno()` (10 error variants)

#### oncrix-drivers
- `Driver` trait, `DeviceRegistry` (64 devices, find by ID/class/IRQ)

#### oncrix-kernel
- 7-phase boot: Serial, GDT, IDT, Heap, Scheduler, SYSCALL, PIC+PIT
- 5 exception handlers, 3 IRQ handlers (timer, keyboard, spurious)
- Context switching, SYSCALL/SYSRET, Ring 0→3 (`iretq`)
- Kernel thread pool (32 threads, 8 KiB stacks)
- ELF64 loader, user-space exec, user pointer validation
- Preemptive scheduling (priority-based time slices)
