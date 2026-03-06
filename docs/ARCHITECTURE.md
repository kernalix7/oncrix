# ONCRIX Architecture

[한국어](ARCHITECTURE.ko.md)

This document is the authoritative technical reference for the ONCRIX operating
system architecture. It covers the design philosophy, kernel structure, hardware
interaction model, comparison with other operating systems, and the full
technical specification of each subsystem.

---

## Table of Contents

1. [Design Philosophy](#design-philosophy)
2. [Kernel Architecture Comparison](#kernel-architecture-comparison)
3. [Layer Architecture](#layer-architecture)
4. [Boot Sequence](#boot-sequence)
5. [Memory Model](#memory-model)
6. [Process & Thread Model](#process--thread-model)
7. [Scheduling](#scheduling)
8. [Inter-Process Communication](#inter-process-communication)
9. [Virtual File System](#virtual-file-system)
10. [System Call Interface](#system-call-interface)
11. [Interrupt & Exception Handling](#interrupt--exception-handling)
12. [Security Architecture](#security-architecture)
13. [POSIX Compatibility Strategy](#posix-compatibility-strategy)
14. [Target Platforms](#target-platforms)
15. [Crate Dependency Graph](#crate-dependency-graph)

---

## Design Philosophy

ONCRIX follows one guiding principle: **minimize the code that runs with full
hardware privilege**. Everything that *can* run in user space *does* run in
user space. The kernel exists only to arbitrate access to hardware resources
and to pass messages between isolated services.

### The Five Pillars

| # | Pillar | Description |
|---|--------|-------------|
| 1 | **Minimal Kernel** | Only scheduling, IPC, and page table management execute in Ring 0. The entire trusted computing base (TCB) stays small and auditable. |
| 2 | **Message-Passing IPC** | All communication between OS services flows through typed, capability-protected IPC channels. No backdoor shared state. |
| 3 | **Capability-Based Security** | Access rights are unforgeable tokens attached to IPC endpoints. A process can only use resources it has been explicitly granted. No ambient authority. |
| 4 | **Fault Isolation** | Drivers, file systems, and network stacks run as ordinary user-space processes. A crashed driver is restarted without affecting the rest of the system. |
| 5 | **POSIX at the Edge** | POSIX compatibility is implemented in user-space libraries and service processes, not baked into the kernel. The kernel itself exposes a message-passing API. |

### Rust as a Systems Language

ONCRIX is written entirely in Rust (`#![no_std]`, zero C code). This is not
a stylistic choice — it is a fundamental safety decision:

| Property | How Rust enforces it |
|----------|---------------------|
| No null dereference | `Option<T>` replaces nullable pointers |
| No buffer overflow | Bounds-checked slices and arrays |
| No use-after-free | Ownership model — single owner, move semantics |
| No data races | Borrow checker prevents `&mut T` aliasing |
| No uninitialized memory | Variables must be initialized before use |

`unsafe` blocks are permitted only for hardware interaction (MMIO, inline
assembly, page table manipulation). Every `unsafe` block carries a
`// SAFETY:` comment documenting the invariant that the programmer upholds.

---

## Kernel Architecture Comparison

### Monolithic vs. Microkernel

```
Monolithic (Linux, FreeBSD)              Microkernel (QNX, ONCRIX)
┌─────────────────────────────┐          ┌─────────────────────────────┐
│       Kernel (Ring 0)       │          │   User Space (Ring 3)       │
│                             │          │  FS server  │ Net server    │
│ Scheduler                   │          │  Drivers    │ Shell         │
│ Memory manager              │          │  → crash = that process dies│
│ File systems (ext4, xfs..)  │          ├─────────────────────────────┤
│ Network stack (TCP/IP)      │          │       Kernel (Ring 0)       │
│ All device drivers          │          │  Scheduler + IPC + Pages    │
│ Security modules            │          │  → minimal attack surface   │
│                             │          │                             │
│ → any bug = kernel panic    │          │  → ~10K LoC at risk         │
│ → ~30M LoC at risk          │          │    (vs ~30M in Linux)       │
└─────────────────────────────┘          └─────────────────────────────┘
```

### Detailed OS Comparison

| | Linux | FreeBSD | QNX | ONCRIX |
|--|-------|---------|-----|--------|
| **Kernel type** | Monolithic | Monolithic (modular) | Microkernel | Microkernel |
| **Ring 0 code** | ~30M LoC | ~millions LoC | < 100K LoC | Minimal (goal) |
| **Language** | C (+ some Rust) | C | C | **Rust** (zero C) |
| **Driver location** | Kernel space | Kernel (some KLDs) | User space | User space |
| **File system** | Kernel space | Kernel space | User-space server | User-space server |
| **IPC model** | Pipes, sockets, signals, futexes | Pipes, sockets, signals | Synchronous message passing | Synchronous message passing |
| **Fault isolation** | None — driver bug = kernel panic | None | Full — service restart | Full — service restart |
| **Security model** | DAC + SELinux / AppArmor | DAC + MAC (Capsicum) | Capability-based | Capability-based |
| **POSIX compliance** | Near-complete (not certified) | Full (POSIX.1 certified) | Full (POSIX.1 certified) | Target: POSIX.1-2024 (Linux x86_64 ABI) |
| **Real-time** | PREEMPT_RT patch required | Limited soft RT | Hard real-time (certified) | Preemptive (not yet RT) |
| **Memory safety** | Manual (C) | Manual (C) | Manual (C) | Compiler-enforced (Rust) |
| **License** | GPL-2.0 | BSD-2-Clause | Proprietary (closed) | **Apache-2.0** |

### What ONCRIX Takes from Each

| Source | What we adopt | What we do differently |
|--------|--------------|----------------------|
| **QNX** | Microkernel structure, message-passing IPC, capability security, fault isolation, service restart | Open source (Apache-2.0), Rust instead of C, no proprietary licensing |
| **Linux** | POSIX syscall ABI (x86_64 numbering), practical compatibility approach, vast ecosystem lessons | Microkernel instead of monolithic, no drivers in Ring 0, Rust instead of C |
| **FreeBSD** | Clean BSD-style code organization, Capsicum capabilities inspiration | Not monolithic, Rust instead of C, message-passing instead of shared kernel state |
| **seL4** | Formal verification mindset, truly minimal TCB (~10K LoC), capability design patterns | Practical POSIX compatibility, Rust safety instead of Isabelle/HOL proofs |
| **MINIX 3** | Self-healing microkernel, automatic driver restart, education-focused design | Rust safety, modern IPC design, production-grade performance goals |

### One-Line Positioning

> **QNX's structural advantages + Rust memory safety + Linux ABI compatibility + open source (Apache-2.0)**

---

## Layer Architecture

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

### Layer Responsibilities

| Layer | Ring | Crates | What it does |
|-------|------|--------|--------------|
| **Bootloader** | — | `oncrix-bootloader` | Multiboot2 handoff, memory map, kernel load |
| **Microkernel** | 0 | `oncrix-kernel` | Scheduler, core IPC dispatch, page table ops, exception/IRQ routing |
| **HAL** | 0 | `oncrix-hal` | GDT/IDT, PIC/APIC, PIT, UART, ACPI — all behind traits |
| **Memory** | 0 | `oncrix-mm` | Physical frame allocator, page tables, kernel heap, address spaces |
| **Process** | 0/3 | `oncrix-process` | Process/thread structs, PID/TID, scheduler, fork, signals |
| **IPC** | 0→3 | `oncrix-ipc` | Channels (ring buffer), endpoint registry, message format |
| **Syscall** | 3→0 | `oncrix-syscall` | POSIX ABI dispatcher, handler stubs, errno mapping |
| **VFS** | 3 | `oncrix-vfs` | Inode/dentry/superblock, ramfs/devfs/procfs, pipes, path resolution |
| **Drivers** | 3 | `oncrix-drivers` | Driver trait, device registry, char/block abstraction |
| **Lib** | — | `oncrix-lib` | Error enum, Result<T>, shared types |

---

## Boot Sequence

The kernel boots through a strict 7-phase initialization sequence. Each phase
depends on the previous one completing successfully.

```
Phase 1: Serial Console
  │  UART 16550 on COM1 (0x3F8), 115200 baud, 8N1
  │  All subsequent output goes here
  v
Phase 2: GDT + TSS
  │  5 segments: null, kernel code (0x08), kernel data (0x10),
  │              user data (0x1B), user code (0x23)
  │  TSS loaded at selector 0x28 (double-fault stack: 16 KiB)
  v
Phase 3: IDT
  │  256 interrupt vectors
  │  Exception handlers: #DE (0), #UD (6), #DF (8, IST1), #GP (13), #PF (14)
  v
Phase 4: Kernel Heap
  │  LinkedListAllocator, 256 KiB
  │  First-fit allocation with coalescing
  v
Phase 5: Scheduler
  │  Round-robin, 256 thread slots
  │  Idle + init kernel threads spawned
  v
Phase 6: SYSCALL/SYSRET
  │  MSR configuration:
  │    EFER (0xC000_0080) — set SCE bit
  │    STAR (0xC000_0081) — kernel CS=0x08, user base=0x10
  │    LSTAR (0xC000_0082) — entry point address
  │    FMASK (0xC000_0084) — mask IF on entry
  v
Phase 7: PIC + PIT
  │  8259 PIC: ICW1-4, remap IRQ 0-15 → vectors 32-47
  │  PIT: channel 0, rate generator mode, ~100 Hz (divisor 11932)
  │  [Optional: APIC timer calibration via PIT channel 2]
  v
  Kernel Ready — halt loop or schedule first task
```

### Memory Layout (Higher-Half)

```
Virtual Address Space (x86_64, 48-bit canonical)
┌──────────────────────────────────────────┐ 0xFFFF_FFFF_FFFF_FFFF
│                                          │
│  Kernel Space                            │
│  Base: 0xFFFF_FFFF_8000_0000             │
│  (higher-half, linker script)            │
│                                          │
├──────────────────────────────────────────┤ 0xFFFF_8000_0000_0000
│                                          │  KERNEL_SPACE_START
│  (Non-canonical hole)                    │
│                                          │
├──────────────────────────────────────────┤ 0x0000_7FFF_FFFF_FFFF
│                                          │  USER_SPACE_END
│  User Space                              │
│  Stack top: USER_SPACE_END - 0xFFF       │
│  Heap (brk): above last PT_LOAD          │
│  Code/Data: loaded from ELF PT_LOAD      │
│  Base: 0x0000_0000_0040_0000             │
│                                          │  USER_SPACE_START
├──────────────────────────────────────────┤ 0x0000_0000_0000_0000
```

---

## Memory Model

### Physical Memory

| Component | Implementation | Details |
|-----------|---------------|---------|
| **Allocator** | Bitmap (`BitmapAllocator`) | 32,768 frames × 4 KiB = **128 MiB** physical RAM |
| **Storage** | `[u64; 512]` | 512 words × 64 bits = 32,768 frame bits |
| **Bit convention** | 0 = free, 1 = used | `mark_range_free()`, `mark_range_used()` |
| **Allocation** | First-fit scan | Scans bitmap words for zero bits |
| **Frame size** | 4,096 bytes | `PAGE_SIZE = 4096`, `PAGE_SHIFT = 12` |

### Virtual Memory

**4-Level Page Tables (x86_64)**:

```
Virtual Address (48-bit canonical):
┌────────┬────────┬────────┬────────┬──────────────┐
│ PML4   │ PDPT   │  PD    │  PT    │   Offset     │
│ [47:39]│ [38:30]│ [29:21]│ [20:12]│   [11:0]     │
│ 9 bits │ 9 bits │ 9 bits │ 9 bits │  12 bits     │
└────────┴────────┴────────┴────────┴──────────────┘
   512      512      512      512     4096 bytes
 entries  entries  entries  entries    per page
```

**Page Table Entry Flags**:

| Bit | Name | Description |
|-----|------|-------------|
| 0 | `PRESENT` | Page is mapped |
| 1 | `WRITABLE` | Page is writable |
| 2 | `USER` | User-mode accessible |
| 3 | `WRITE_THROUGH` | Write-through caching |
| 4 | `NO_CACHE` | Disable caching |
| 5 | `ACCESSED` | Set by CPU on access |
| 6 | `DIRTY` | Set by CPU on write |
| 7 | `HUGE_PAGE` | 2 MiB page (PD level) or 1 GiB (PDPT level) |
| 8 | `GLOBAL` | Not flushed on CR3 switch |
| 63 | `NO_EXECUTE` | NX — disable instruction fetch |

**TLB Management**: `flush_tlb_page(addr)` uses `invlpg`, `flush_tlb_all()`
reloads `CR3`.

### Kernel Heap

| Property | Value |
|----------|-------|
| Allocator | `LinkedListAllocator` |
| Size | 256 KiB |
| Algorithm | First-fit with free-block splitting and coalescing |
| Block header | `FreeBlock { size: usize, next: *mut FreeBlock }` |
| Alignment | Respects requested alignment via padding |
| Thread safety | `UnsafeCell` wrapper (single-core assumption) |

### Per-Process Address Space

| Property | Value |
|----------|-------|
| Structure | `AddressSpace` |
| PML4 storage | Physical address of root page table |
| Max regions | 64 `VmRegion` slots |
| Overlap check | Linear scan on `add_region()` |
| USER_SPACE_START | `0x0000_0000_0040_0000` |
| USER_SPACE_END | `0x0000_7FFF_FFFF_FFFF` |
| KERNEL_SPACE_START | `0xFFFF_8000_0000_0000` |

**VmRegion**:

```rust
pub struct VmRegion {
    pub start: VirtAddr,  // Page-aligned start
    pub size: usize,      // Region size in bytes
    pub prot: Protection, // READ | WRITE | EXEC
    pub kind: RegionKind, // Code, Data, Heap, Stack, Mmap
}
```

**Protection flags**: `READ = 0b001`, `WRITE = 0b010`, `EXEC = 0b100`.
Combinations: `RW = 0b011`, `RX = 0b101`, `RWX = 0b111`.

---

## Process & Thread Model

### Process

```rust
pub struct Process {
    pid: Pid,                              // u64 newtype
    state: ProcessState,                   // Active | Exited
    threads: [Option<Tid>; 64],            // Up to 64 threads
    thread_count: usize,
}
```

**PID allocation**: Atomic `fetch_add` on global `NEXT_PID` counter (Relaxed
ordering). `Pid(0)` is reserved as `KERNEL`.

### Thread

```rust
pub struct Thread {
    tid: Tid,                // u64 newtype
    pid: Pid,                // Owning process
    state: ThreadState,      // Ready | Running | Blocked | Exited
    priority: Priority,      // 0 (highest) — 255 (idle)
    stack_pointer: u64,      // Saved RSP for context switch
}
```

**Priority levels**: `HIGHEST = 0`, `NORMAL = 128`, `IDLE = 255`.

### Context Switch (x86_64)

The context switch saves and restores the 6 callee-saved registers plus RSP
and RIP:

```rust
pub struct CpuContext {
    pub rbx: u64,
    pub rbp: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rsp: u64,
    pub rip: u64,
}
```

`switch_context(old: *mut CpuContext, new: *const CpuContext)` is pure inline
assembly that:
1. Pushes `rbx, rbp, r12-r15` to the current stack
2. Saves RSP to `old.rsp`
3. Loads RSP from `new.rsp`
4. Pops `r15-r12, rbp, rbx` from the new stack
5. Returns (RIP is on the new stack)

### Fork

`fork_process(parent, priority)` → `(ForkResult, Process, Thread)`:
1. Allocates a new PID and TID atomically
2. Creates child `Process` with the new PID
3. Adds the child TID to the child's thread list
4. Creates a child `Thread` inheriting the parent's priority
5. Returns the child objects — the *caller* is responsible for:
   - Duplicating page tables with CoW mappings
   - Copying the parent's CPU context
   - Setting RAX = 0 in the child's context
   - Adding the child thread to the scheduler

**Copy-on-Write Tracker**:

```rust
pub struct CowTracker {
    states: [CowState; 4096],  // Per-frame state
    count: usize,              // Number of shared frames
}

pub enum CowState {
    Shared(u16),   // Reference count (≥ 2)
    Exclusive,     // Single owner, writable
}
```

- `share(frame_idx)`: `Exclusive → Shared(2)`, `Shared(n) → Shared(n+1)`
- `unshare(frame_idx)`: `Shared(n>2) → Shared(n-1)`, `Shared(2) → Exclusive`

### Signal Handling

| Property | Value |
|----------|-------|
| Max signals | 32 (POSIX standard set) |
| Storage | `u32` bitsets for mask and pending |
| Actions per signal | `Default`, `Ignore`, `Handler(u64)` (handler address) |

**Defined signals**: SIGHUP(1), SIGINT(2), SIGQUIT(3), SIGILL(4), SIGABRT(6),
SIGBUS(7), SIGFPE(8), SIGKILL(9), SIGSEGV(11), SIGPIPE(13), SIGALRM(14),
SIGTERM(15), SIGCHLD(17), SIGCONT(18), SIGSTOP(19), SIGTSTP(20).

---

## Scheduling

### Round-Robin Scheduler

| Property | Value |
|----------|-------|
| Max threads | 256 |
| Algorithm | Cursor-based round-robin with priority time slices |
| Operations | `add()`, `remove()`, `schedule()`, `block_current()`, `unblock()` |

### Preemptive Scheduling

The scheduler is timer-driven. On each PIT tick (~100 Hz = 10 ms interval):

1. `timer_tick()` decrements `remaining_ticks`
2. When `remaining_ticks` reaches 0 → forced context switch
3. New thread gets a time slice based on its priority

**Priority → Time Slice Mapping**:

```
Priority 0   (highest) → 50 ticks (500 ms)
Priority 128 (normal)  → 25 ticks (250 ms)
Priority 255 (idle)    →  1 tick  (10 ms)

Formula: slice = MAX_SLICE - (priority * (MAX_SLICE - MIN_SLICE) / 255)
         where MAX_SLICE = 50, MIN_SLICE = 1
```

**Preemption Control** (nestable):

```rust
pub struct PreemptionState {
    remaining_ticks: u32,    // Ticks left in current slice
    total_ticks: u64,        // Total ticks since boot
    preempt_enabled: bool,   // Master enable flag
    preempt_count: u32,      // Nesting depth
    forced_switches: u64,    // Stats: preemption events
    voluntary_yields: u64,   // Stats: yield() calls
}
```

- `disable()` increments `preempt_count`, sets `preempt_enabled = false`
- `enable()` decrements `preempt_count`, re-enables when count reaches 0
- Returns `true` if a deferred switch is needed (slice expired while disabled)

### Kernel Thread Pool

| Property | Value |
|----------|-------|
| Max threads | 32 |
| Stack size | 8 KiB per thread |
| Initial threads | `idle_thread_entry()`, `init_thread_entry()` |
| Stack storage | Static arrays (`KTHREAD_STACKS`) |

---

## Inter-Process Communication

IPC is the backbone of the microkernel. All service communication goes through
typed message channels.

### Message Format

```rust
pub struct Message {
    header: MessageHeader,
    payload: [u8; 256],        // MAX_INLINE_PAYLOAD = 256
}

pub struct MessageHeader {
    pub sender: EndpointId,    // u64
    pub receiver: EndpointId,  // u64
    pub tag: u32,              // Message type identifier
    pub payload_len: u32,      // Actual payload bytes (0..256)
}
```

### Channel

Each channel is a **unidirectional ring buffer** connecting two endpoints:

```rust
pub struct Channel {
    src: EndpointId,
    dst: EndpointId,
    buffer: [MessageSlot; 16],  // CHANNEL_CAPACITY = 16
    head: usize,                // Next read position
    tail: usize,                // Next write position
    count: usize,               // Messages in buffer
}
```

**MessageSlot**: `occupied: bool`, `sender: EndpointId`, `tag: u32`,
`payload_len: u32`, `payload: [u8; 256]`.

### Channel Registry

- Capacity: **64 channels**
- Lookup: by endpoint pair `(src, dst)`
- Operations: `create(src, dst)`, `find(src, dst)`, `remove(id)`

### SyncIpc Trait

```rust
pub trait SyncIpc {
    fn send(&mut self, msg: &Message) -> Result<()>;
    fn receive(&mut self) -> Result<Message>;
    fn reply(&mut self, msg: &Message) -> Result<()>;
    fn call(&mut self, request: &Message) -> Result<Message>;  // send + receive
}
```

---

## Virtual File System

### Architecture

```
                  vfs_open() / vfs_read() / vfs_write()
                              │
              ┌───────────────┼───────────────┐
              v               v               v
         ┌────────┐     ┌────────┐     ┌────────┐
         │ ramfs  │     │ devfs  │     │ procfs │
         └────────┘     └────────┘     └────────┘
              │               │               │
              v               v               v
         InodeOps trait implementation per filesystem
```

### Core Types

**Inode**:
```rust
pub struct Inode {
    pub ino: InodeNumber,     // u64 newtype
    pub file_type: FileType,  // Regular | Directory | Symlink | CharDevice |
                              // BlockDevice | Fifo | Socket
    pub mode: FileMode,       // u16 — POSIX permission bits
    pub size: u64,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
}
```

**InodeOps Trait** — every filesystem must implement:

| Method | Signature | Description |
|--------|-----------|-------------|
| `lookup` | `(&self, dir: InodeNumber, name: &[u8]) → Result<InodeNumber>` | Find child by name |
| `create` | `(&mut self, dir: InodeNumber, name: &[u8], mode: FileMode) → Result<InodeNumber>` | Create regular file |
| `mkdir` | `(&mut self, dir: InodeNumber, name: &[u8], mode: FileMode) → Result<InodeNumber>` | Create directory |
| `unlink` | `(&mut self, dir: InodeNumber, name: &[u8]) → Result<()>` | Remove file |
| `rmdir` | `(&mut self, dir: InodeNumber, name: &[u8]) → Result<()>` | Remove directory |
| `read` | `(&self, ino: InodeNumber, offset: u64, buf: &mut [u8]) → Result<usize>` | Read data |
| `write` | `(&mut self, ino: InodeNumber, offset: u64, data: &[u8]) → Result<usize>` | Write data |
| `truncate` | `(&mut self, ino: InodeNumber, size: u64) → Result<()>` | Set file size |

### File Descriptor Table

| Property | Value |
|----------|-------|
| Max open files | 256 (`MAX_OPEN_FILES`) |
| Reserved FDs | `STDIN = 0`, `STDOUT = 1`, `STDERR = 2` |
| Operations | `alloc()`, `get()`, `get_mut()`, `close()`, `dup2()` |

**OpenFile**:
```rust
pub struct OpenFile {
    pub inode: InodeNumber,
    pub offset: u64,
    pub flags: OpenFlags,
}
```

**OpenFlags**: `O_RDONLY = 0`, `O_WRONLY = 1`, `O_RDWR = 2`,
`O_CREAT = 0o100`, `O_TRUNC = 0o1000`, `O_APPEND = 0o2000`.

### Filesystems

**ramfs** — In-memory filesystem:

| Property | Value |
|----------|-------|
| Max inodes | 128 |
| Max file size | 4,096 bytes (1 page) |
| Max dir entries | 32 per directory |
| Name length | 255 bytes |
| Data storage | Inline `[u8; 4096]` per file |

**devfs** — Device filesystem:

| Property | Value |
|----------|-------|
| Max device nodes | 64 |
| Device types | Char, Block |
| Operations | Register, unregister, lookup by name |

**procfs** — Process information filesystem:

| Virtual file | Content |
|-------------|---------|
| `/proc/version` | OS version string |
| `/proc/uptime` | System uptime |
| `/proc/meminfo` | Memory usage statistics |
| `/proc/cpuinfo` | CPU information |

### Pipe

| Property | Value |
|----------|-------|
| Buffer size | 4,096 bytes (ring buffer) |
| Max pipes | 64 (`PipeRegistry`) |
| Semantics | POSIX — EOF when write end closed, EPIPE when read end closed |

**State machine**:
- `read()` on empty pipe + write open → `WouldBlock`
- `read()` on empty pipe + write closed → `Ok(0)` (EOF)
- `write()` on pipe + read closed → `IoError` (EPIPE)
- `write()` on full pipe → `WouldBlock`

### Path Resolution

`resolve_path(path, root_inode, fs, mount_table, dcache)`:
1. Split path by `/` into up to 64 components
2. Start at `root_inode`
3. For each component:
   - Skip `.` (current directory)
   - Call `fs.lookup(current_dir, component)` → child inode
   - Verify child is a directory (except for last component)
   - Advance to child
4. Return final inode number

`vfs_open(path, flags, mode, ...)`:
- Resolves path, handles `O_CREAT` (creates file if not found), `O_TRUNC`
  (truncates existing file to 0), caches new dentry entries.

### VFS Operations

| Operation | Behavior |
|-----------|----------|
| `vfs_read(fd_table, fd, buf, fs, lookup)` | Read from fd's offset, advance offset |
| `vfs_write(fd_table, fd, data, fs, lookup)` | Write at offset (or end if O_APPEND), advance offset |
| `vfs_lseek(fd_table, fd, offset, whence, lookup)` | SEEK_SET(0), SEEK_CUR(1), SEEK_END(2) with overflow check |
| `vfs_stat(inode)` → `StatInfo` | Encode FileType + FileMode into POSIX `st_mode` |

**st_mode encoding**: Regular=`0o100000`, Directory=`0o040000`,
Symlink=`0o120000`, CharDevice=`0o020000`, BlockDevice=`0o060000`,
Fifo=`0o010000`, Socket=`0o140000`. Combined with permission bits (`mode & 0o7777`).

---

## System Call Interface

### ABI

ONCRIX uses the **Linux x86_64 syscall ABI** for binary compatibility:

| Register | Purpose |
|----------|---------|
| `RAX` | Syscall number |
| `RDI` | Argument 0 |
| `RSI` | Argument 1 |
| `RDX` | Argument 2 |
| `R10` | Argument 3 |
| `R8` | Argument 4 |
| `R9` | Argument 5 |
| `RAX` (return) | Result (negative = -errno) |

Entry via `SYSCALL` instruction → kernel's `LSTAR` handler → `dispatch()`.

### Syscall Table

| Number | Name | Category |
|--------|------|----------|
| 0 | `read` | I/O |
| 1 | `write` | I/O |
| 2 | `open` | Files |
| 3 | `close` | Files |
| 4 | `stat` | Files |
| 5 | `fstat` | Files |
| 8 | `lseek` | Files |
| 9 | `mmap` | Memory |
| 11 | `munmap` | Memory |
| 12 | `brk` | Memory |
| 13 | `rt_sigaction` | Signals |
| 22 | `pipe` | IPC |
| 33 | `dup2` | Files |
| 39 | `getpid` | Process |
| 57 | `fork` | Process |
| 59 | `execve` | Process |
| 60 | `exit` | Process |
| 61 | `wait4` | Process |
| 62 | `kill` | Signals |
| 83 | `mkdir` | Files |
| 84 | `rmdir` | Files |
| 87 | `unlink` | Files |
| 512 | `ipc_send` | ONCRIX IPC |
| 513 | `ipc_receive` | ONCRIX IPC |
| 514 | `ipc_reply` | ONCRIX IPC |
| 515 | `ipc_call` | ONCRIX IPC |
| 516 | `ipc_create_endpoint` | ONCRIX IPC |

Unknown syscall numbers return `-38` (`ENOSYS`).

### Error Mapping

| `oncrix_lib::Error` | POSIX errno | Value |
|---------------------|-------------|-------|
| `PermissionDenied` | `EACCES` | -13 |
| `NotFound` | `ENOENT` | -2 |
| `OutOfMemory` | `ENOMEM` | -12 |
| `InvalidArgument` | `EINVAL` | -22 |
| `Busy` | `EBUSY` | -16 |
| `WouldBlock` | `EAGAIN` | -11 |
| `Interrupted` | `EINTR` | -4 |
| `IoError` | `EIO` | -5 |
| `NotImplemented` | `ENOSYS` | -38 |
| `AlreadyExists` | `EEXIST` | -17 |

### User Pointer Validation

Before any kernel dereference of a user-space pointer:

```rust
fn validate_user_range(ptr: u64, len: usize) -> Result<()> {
    // 1. ptr >= USER_SPACE_START (0x0000_0000_0040_0000)
    // 2. ptr + len does not wrap around
    // 3. ptr + len <= USER_SPACE_END + 1 (0x0000_8000_0000_0000)
}
```

Functions: `copy_from_user(dst, src, len)`, `copy_to_user(dst, src, len)`,
`validate_user_string(ptr, max_len)`, `get_user_u64(addr)` (8-byte aligned),
`put_user_u64(addr, value)` (8-byte aligned).

---

## Interrupt & Exception Handling

### IDT Layout

| Vector | Source | Handler |
|--------|--------|---------|
| 0 | #DE — Divide Error | Prints RIP, halts |
| 6 | #UD — Invalid Opcode | Prints RIP, halts |
| 8 | #DF — Double Fault | IST1 (separate 16 KiB stack), halts |
| 13 | #GP — General Protection | Prints error code + RIP, halts |
| 14 | #PF — Page Fault | Prints CR2 + error code + RIP, halts |
| 32 | IRQ 0 — PIT Timer | Increments tick counter, calls scheduler |
| 33 | IRQ 1 — Keyboard | Reads scancode from port 0x60 |
| 39 | IRQ 7 — Spurious | No EOI sent |

### 8259 PIC Configuration

```
Master PIC (ports 0x20/0x21)        Slave PIC (ports 0xA0/0xA1)
  IRQ 0 → Vector 32 (Timer)          IRQ 8  → Vector 40
  IRQ 1 → Vector 33 (Keyboard)       IRQ 9  → Vector 41
  IRQ 2 → Vector 34 (Cascade)        ...
  ...                                 IRQ 15 → Vector 47
  IRQ 7 → Vector 39 (Spurious)

ICW sequence: ICW1=0x11, ICW2=offset, ICW3=cascade, ICW4=0x01 (8086 mode)
EOI: write 0x20 to command port (both master + slave for IRQ ≥ 8)
```

### Local APIC Timer

| Register | Offset | Description |
|----------|--------|-------------|
| ID | 0x020 | APIC ID |
| Version | 0x030 | Version and max LVT |
| TPR | 0x080 | Task Priority |
| EOI | 0x0B0 | End of Interrupt (write 0) |
| SIVR | 0x0F0 | Spurious Interrupt Vector (bit 8 = APIC enable) |
| LVT Timer | 0x320 | Timer vector + mode (one-shot / periodic) |
| Initial Count | 0x380 | Countdown start value |
| Current Count | 0x390 | Current countdown (read-only) |
| Divide Config | 0x3E0 | Timer frequency divider |

**MMIO base**: `0xFEE0_0000`

**Calibration algorithm**:
1. Set APIC divide to By16, initial count to `0xFFFF_FFFF`
2. Program PIT channel 2 for ~10 ms delay (speaker gate)
3. Wait for PIT to elapse
4. Read APIC current count → elapsed ticks in 10 ms
5. Calculate frequency: `elapsed * 100 * divide_value`

**Timer modes**: One-shot (`0b00 << 17`), Periodic (`0b01 << 17`).
Masked: bit 16 set in LVT.

### ACPI Table Parsing

**RSDP** (Root System Description Pointer):
- Signature: `"RSD PTR "` (8 bytes, trailing space)
- Search: BIOS ROM `0xE0000`–`0xFFFFF`, 16-byte boundaries
- Checksum: sum of first 20 bytes = 0 (v1), sum of 36 bytes = 0 (v2)
- Returns: `RsdpInfo { revision, rsdt_address, xsdt_address }`

**XSDT** (Extended System Description Table):
- Signature: `"XSDT"` (4 bytes)
- Checksum: sum of all bytes = 0
- Entries: array of 64-bit physical addresses (up to 32)

**MADT** (Multiple APIC Description Table):
- Signature: `"APIC"` (4 bytes)
- Contains: Local APIC address (32-bit)
- Variable-length entries (type + length header):
  - Type 0: Local APIC (APIC ID, processor ID, flags)
  - Type 1: I/O APIC (ID, address, GSI base)
  - Type 2: Interrupt Source Override (bus, source, GSI, flags)
- Limits: 64 Local APICs, 8 I/O APICs, 16 Overrides

---

## Security Architecture

### Capability Model

```
Process A                         Process B
┌──────────┐                     ┌──────────┐
│ Cap: FS  │──── IPC channel ────│ Cap: Net │
│ Cap: Net │     (capability      │          │
│          │      checked)        │          │
└──────────┘                     └──────────┘
```

- Each IPC endpoint carries a capability token
- Capabilities are unforgeable — only the kernel can mint them
- A process cannot access a service unless it holds the matching capability
- Capabilities can be delegated (passed through IPC) with restricted rights

### Privilege Separation

| Ring | What runs | Trust level |
|------|-----------|-------------|
| Ring 0 | Microkernel (scheduler, IPC, page tables) | Full trust |
| Ring 3 | Everything else (drivers, FS, net, apps) | Untrusted |

Even device drivers — traditionally the most crash-prone kernel code — run
in Ring 3 with no direct hardware access. They request I/O through
capability-gated IPC to the kernel.

### User Pointer Validation

All system calls that accept user-space pointers **must** validate them
before dereferencing:

1. Pointer falls within `USER_SPACE_START..=USER_SPACE_END`
2. `ptr + len` does not overflow (wrap around)
3. `ptr + len` does not exceed `USER_SPACE_END + 1`
4. For `u64` operations: 8-byte alignment required

Violation returns `Error::InvalidArgument`.

---

## POSIX Compatibility Strategy

### Target Standard

**POSIX.1-2024 (IEEE Std 1003.1-2024)** — the latest revision, published
June 2024. Available for free at
[The Open Group](https://pubs.opengroup.org/onlinepubs/9799919799/).

Why 2024 over 2017:
- No legacy baggage — ONCRIX is built from scratch, so deprecated functions
  (`tmpnam`, `gets`, etc.) are simply not implemented
- C17 alignment matches Rust's type model better than C99
- Nanosecond timestamps (`_POSIX_TIMESTAMP_RESOLUTION`) required from the start
- `getentropy()` for secure random — fits capability-based security model

ONCRIX does **not** seek POSIX certification (which requires The Open Group
commercial licensing). The project describes itself as **"POSIX.1-2024
compatible"** — a factual technical statement, not a trademark.

### Beyond POSIX: Linux ABI Compatibility

POSIX alone is insufficient for running real-world applications. Most binaries
are built for Linux, not abstract POSIX. ONCRIX targets practical compatibility
in three layers:

| Layer | What | Why |
|-------|------|-----|
| **POSIX.1-2024 core** | File I/O, process, signals, threads, pipes | Base compatibility standard |
| **Linux extensions** | `epoll`, `eventfd`, `timerfd`, `signalfd`, `/proc` layout | Most real apps depend on these |
| **libc** | musl port or Rust-native (relibc-style) | Required for C/C++ binary execution |

### Architecture

ONCRIX does not implement POSIX in the kernel. Instead:

```
User Binary
  │  syscall instruction (RAX = syscall number)
  v
Kernel SYSCALL Handler
  │  Validates arguments, checks capabilities
  v
IPC Message to Service
  │  Translates syscall into typed IPC message
  v
Service Process (user space)
  │  VFS server, process server, network server, etc.
  │  Performs actual work
  v
IPC Reply
  │  Result sent back through IPC
  v
Kernel SYSRET
  │  Returns result in RAX to user binary
  v
User Binary continues
```

1. **Syscall numbers** match Linux x86_64 ABI (read=0, write=1, open=2, ...)
2. **Syscall dispatcher** translates POSIX calls into internal IPC messages
3. **VFS server** (user space) handles file operations
4. **Process server** (user space) handles fork/exec/wait
5. Existing Unix binaries see a standard POSIX interface

The kernel never needs to understand "files" or "processes" in the POSIX
sense — it only knows about address spaces, threads, and messages.

### ELF Loader

| Property | Value |
|----------|-------|
| Format | ELF64 (64-bit, little-endian) |
| Magic | `0x7F, 'E', 'L', 'F'` |
| Supported types | `ET_EXEC` (static), `ET_DYN` (PIE) |
| Architecture | `EM_X86_64` only (currently) |
| Max segments | 16 loadable (`PT_LOAD`) |
| Max ELF size | 16 MiB |
| User stack | 64 KiB at `USER_SPACE_END - 0xFFF` |

`prepare_exec(elf_data)` flow:
1. Parse and validate ELF header
2. Create `AddressSpace` with new PML4
3. For each `PT_LOAD` segment → create `VmRegion` with appropriate protection
4. Set up user stack (64 KiB, `Protection::RW`)
5. Compute initial `brk` (page-aligned end of highest segment)
6. Return `ExecInfo { entry, stack_top, brk, ... }`

---

## Target Platforms

| Architecture | Status | Notes |
|-------------|--------|-------|
| **x86_64** | Primary | All current implementation |
| **aarch64** | Planned | HAL module structure prepared |
| **riscv64** | Planned | HAL module structure prepared |

Architecture-specific code is isolated in `oncrix-hal` behind
`#[cfg(target_arch = "...")]` gates. Adding a new architecture means
implementing the HAL traits (`SerialPort`, `InterruptController`, `Timer`)
— no changes to upper-layer crates.

---

## Crate Dependency Graph

```
                    ┌──────────┐
                    │  kernel  │  ← Top: integrates everything
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
       │            lib              │  ← Bottom: shared types, zero deps
       └─────────────────────────────┘
```

**Dependency rule**: Crates at lower layers never depend on crates above them.
All kernel-space crates have **zero external dependencies** (only `core` and
`alloc`). `oncrix-lib` is the leaf with no dependencies at all.

---

## Tech Stack

| Component | Choice |
|-----------|--------|
| Language | Rust 1.85+ (Edition 2024) |
| Build system | Cargo workspace |
| Kernel mode | `#![no_std]` + `#![no_main]` |
| Assembly | `core::arch::asm!` (inline, arch-gated) |
| Boot protocol | Multiboot2 |
| Test runner | QEMU (x86_64 system emulation) |
| CI/CD | GitHub Actions (fmt + clippy + build) |
| License | Apache-2.0 |
