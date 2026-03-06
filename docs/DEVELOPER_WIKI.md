# ONCRIX Developer Wiki

[한국어](DEVELOPER_WIKI.ko.md)

Crate-by-crate implementation reference for ONCRIX developers.
For the architectural overview and design philosophy, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Table of Contents

1. [oncrix-lib](#oncrix-lib)
2. [oncrix-hal](#oncrix-hal)
3. [oncrix-bootloader](#oncrix-bootloader)
4. [oncrix-mm](#oncrix-mm)
5. [oncrix-ipc](#oncrix-ipc)
6. [oncrix-process](#oncrix-process)
7. [oncrix-vfs](#oncrix-vfs)
8. [oncrix-drivers](#oncrix-drivers)
9. [oncrix-syscall](#oncrix-syscall)
10. [oncrix-kernel](#oncrix-kernel)
11. [Error Handling Patterns](#error-handling-patterns)
12. [Testing Strategy](#testing-strategy)
13. [Build & CI](#build--ci)
14. [Glossary](#glossary)

---

## oncrix-lib

**Path**: `crates/lib/src/lib.rs`
**Role**: Foundational types shared by every other crate.
**Dependencies**: None (`core` only).

### Error Enum

```rust
pub enum Error {
    PermissionDenied,   // EACCES (-13)
    NotFound,           // ENOENT (-2)
    OutOfMemory,        // ENOMEM (-12)
    InvalidArgument,    // EINVAL (-22)
    Busy,               // EBUSY (-16)
    WouldBlock,         // EAGAIN (-11)
    Interrupted,        // EINTR (-4)
    IoError,            // EIO (-5)
    NotImplemented,     // ENOSYS (-38)
    AlreadyExists,      // EEXIST (-17)
}
```

Implements `Display` (human-readable), `Debug` (Rust format).

### Result Type

```rust
pub type Result<T> = core::result::Result<T, Error>;
```

All fallible operations across the kernel return this type.
Use `?` for propagation — never `unwrap()` or `expect()` in production paths.

---

## oncrix-hal

**Path**: `crates/hal/src/`
**Role**: Hardware Abstraction Layer — all arch-specific code lives here.
**Dependencies**: `oncrix-lib`

### Trait Definitions

#### SerialPort (`serial.rs`)

```rust
pub trait SerialPort {
    fn write_byte(&mut self, byte: u8) -> Result<()>;
    fn write_str(&mut self, s: &str) -> Result<()>;
    fn read_byte(&self) -> Result<u8>;
}
```

#### InterruptController (`interrupt.rs`)

```rust
pub trait InterruptController {
    fn enable(&mut self, vector: InterruptVector) -> Result<()>;
    fn disable(&mut self, vector: InterruptVector) -> Result<()>;
    fn acknowledge(&mut self, vector: InterruptVector) -> Result<()>;
    fn is_enabled(&self, vector: InterruptVector) -> bool;
    fn enable_all(&mut self);
    fn disable_all(&mut self);
}
```

`InterruptVector` is a `u8` newtype.

#### Timer (`timer.rs`)

```rust
pub trait Timer {
    fn frequency_hz(&self) -> u64;
    fn current_ticks(&self) -> u64;
    fn set_oneshot(&mut self, ticks: u64) -> Result<()>;
    fn set_periodic(&mut self, ticks: u64) -> Result<()>;
    fn stop(&mut self) -> Result<()>;
    fn nanos_to_ticks(&self, nanos: u64) -> u64;
    fn ticks_to_nanos(&self, ticks: u64) -> u64;
}
```

### x86_64 Implementations

#### UART 16550 (`arch/x86_64/uart.rs`)

| Port | COM1 base | COM2 base |
|------|-----------|-----------|
| Data (THR/RBR) | 0x3F8 + 0 | 0x2F8 + 0 |
| IER | +1 | +1 |
| FCR | +2 | +2 |
| LCR | +3 | +3 |
| MCR | +4 | +4 |
| LSR | +5 | +5 |
| DLL (DLAB=1) | +0 | +0 |
| DLH (DLAB=1) | +1 | +1 |

**Init sequence** (115200 baud, 8N1):
1. Disable interrupts (`IER = 0`)
2. Set DLAB (`LCR |= 0x80`), write divisor 1 (`DLL = 1, DLH = 0`)
3. Clear DLAB, set 8N1 (`LCR = 0x03`)
4. Enable FIFO (`FCR = 0xC7`)
5. Set DTR + RTS + OUT2 (`MCR = 0x0B`)

**LSR flags**: `DATA_READY = 0x01`, `TX_EMPTY = 0x20`.

Port I/O uses inline assembly `inb`/`outb` from `io.rs`:

```rust
pub unsafe fn outb(port: u16, value: u8) {
    // SAFETY: Caller ensures port is valid.
    asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack));
}

pub unsafe fn inb(port: u16) -> u8 {
    // SAFETY: Caller ensures port is valid.
    let value: u8;
    asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack));
    value
}
```

#### GDT (`arch/x86_64/gdt.rs`)

**Segment layout** (7 entries, 2 for TSS):

| Index | Selector | Type | DPL |
|-------|----------|------|-----|
| 0 | 0x00 | Null | — |
| 1 | 0x08 | Kernel Code (64-bit, long mode) | 0 |
| 2 | 0x10 | Kernel Data | 0 |
| 3 | 0x18 | User Data | 3 |
| 4 | 0x20 | User Code (64-bit, long mode) | 3 |
| 5-6 | 0x28 | TSS (16 bytes, 2 GDT slots) | 0 |

**Note**: User selectors include RPL=3 bits: `USER_DATA = 0x1B`, `USER_CODE = 0x23`.

**TSS** (104 bytes): `privilege_stacks[3]` (RSP0-2), `ist[7]` (IST1-7).
Double-fault handler uses IST1 with a dedicated 16 KiB stack.

#### IDT (`arch/x86_64/idt.rs`)

256 entries, each 16 bytes:

```rust
pub struct IdtEntry {
    offset_low: u16,       // Handler address [15:0]
    segment_selector: u16, // Code segment (0x08)
    ist: u8,               // IST index (0 = no IST)
    type_attr: u8,         // Gate type + DPL + Present
    offset_mid: u16,       // Handler address [31:16]
    offset_high: u32,      // Handler address [63:32]
    reserved: u32,
}
```

Gate types: `INTERRUPT = 0x8E` (clears IF), `TRAP = 0x8F` (preserves IF).

#### 8259 PIC (`arch/x86_64/pic.rs`)

**I/O ports**:

| PIC | Command | Data |
|-----|---------|------|
| Master | 0x20 | 0x21 |
| Slave | 0xA0 | 0xA1 |

**ICW sequence**:

```
ICW1 = 0x11 (init + ICW4 needed)
ICW2 = offset (master: 32, slave: 40)
ICW3 = cascade (master: 0x04 = IRQ2, slave: 0x02 = cascade ID)
ICW4 = 0x01 (8086 mode)
```

**Operations**: `mask(irq)`, `unmask(irq)`, `send_eoi(irq)`.
For slave IRQs (8-15), EOI is sent to both slave and master.

#### PIT 8254 (`arch/x86_64/pit.rs`)

| Constant | Value |
|----------|-------|
| Base frequency | 1,193,182 Hz |
| Divisor (~100 Hz) | 11,932 |
| Channel 0 port | 0x40 |
| Command port | 0x43 |

**Modes**: `RATE_GEN = 0x34` (mode 2, periodic), `ONESHOT = 0x30` (mode 0).

Divisor is written low-byte then high-byte to the channel 0 port.

#### Local APIC Timer (`arch/x86_64/apic.rs`)

**MMIO registers** (base `0xFEE0_0000`):

| Name | Offset | Access |
|------|--------|--------|
| APIC ID | 0x020 | R |
| Version | 0x030 | R |
| Task Priority (TPR) | 0x080 | R/W |
| End of Interrupt (EOI) | 0x0B0 | W |
| Spurious Int Vector (SIVR) | 0x0F0 | R/W |
| LVT Timer | 0x320 | R/W |
| Timer Initial Count | 0x380 | R/W |
| Timer Current Count | 0x390 | R |
| Timer Divide Config | 0x3E0 | R/W |

**TimerDivide** values: `By1=0b1011`, `By2=0b0000`, `By4=0b0001`,
`By8=0b0010`, `By16=0b0011`, `By32=0b1000`, `By64=0b1001`, `By128=0b1010`.

**LocalApicTimer struct**:

```rust
pub struct LocalApicTimer {
    base_addr: u64,          // 0xFEE0_0000
    timer_vector: u8,        // Interrupt vector for timer
    frequency_hz: u64,       // Calibrated frequency
    tick_count: u64,         // Running counter
    divide: TimerDivide,     // Current divider setting
}
```

**Calibration** (`calibrate_with_pit()`):
1. Set divide to `By16`
2. Set initial count to `0xFFFF_FFFF`
3. Call `pit_sleep_10ms()` — programs PIT channel 2 via speaker gate
4. Read current count → elapsed = `0xFFFF_FFFF - current`
5. `frequency_hz = elapsed * 100 * 16` (100 = 1000ms/10ms, 16 = divide)

**Timer modes**: `ONE_SHOT = 0b00 << 17`, `PERIODIC = 0b01 << 17`.
`LVT_MASKED = 1 << 16`. `SIVR_APIC_ENABLE = 1 << 8`.

### ACPI (`acpi.rs`)

**RSDP structure** (`repr(C, packed)`):

```rust
pub struct RsdpDescriptor {
    signature: [u8; 8],      // "RSD PTR "
    checksum: u8,            // Sum of first 20 bytes = 0
    oem_id: [u8; 6],
    revision: u8,            // 0 = ACPI 1.0, 2 = ACPI 2.0+
    rsdt_address: u32,       // 32-bit RSDT address (v1)
}

pub struct RsdpDescriptor20 {
    first_part: RsdpDescriptor,
    length: u32,
    xsdt_address: u64,      // 64-bit XSDT address (v2)
    extended_checksum: u8,   // Sum of 36 bytes = 0
    reserved: [u8; 3],
}
```

**`find_rsdp()`**: Scans `0xE0000`–`0xFFFFF` on 16-byte boundaries for the
`"RSD PTR "` signature.

**XSDT**: Header (36 bytes) + array of `u64` addresses.
Max entries: 32 (`(xsdt.length - 36) / 8`, capped).

**MADT** (`"APIC"` signature):
- `local_apic_address: u32` at offset 36
- Variable-length entries starting at offset 44:

| Type | Length | Content |
|------|--------|---------|
| 0 | 8 | Local APIC: processor_id, apic_id, flags |
| 1 | 12 | I/O APIC: id, address, gsi_base |
| 2 | 10 | Int Source Override: bus, source, gsi, flags |

**MadtInfo limits**: 64 Local APICs, 8 I/O APICs, 16 Overrides.

All ACPI structures use `read_unaligned()` for field access due to
`repr(C, packed)`.

---

## oncrix-bootloader

**Path**: `crates/bootloader/src/`
**Role**: Boot protocol structures and kernel handoff.
**Dependencies**: `oncrix-lib`

### Key Structures

```rust
pub struct BootInfo {
    pub memory_map: MemoryMap,
    pub kernel_phys_addr: u64,
    pub kernel_size: u64,
    pub rsdp_addr: Option<u64>,
    pub framebuffer: Option<FramebufferInfo>,
}

pub struct MemoryMap {
    pub regions: [MemoryRegion; 128],  // MAX_MEMORY_REGIONS = 128
    pub count: usize,
}

pub struct MemoryRegion {
    pub start: u64,
    pub length: u64,
    pub kind: MemoryRegionKind,
}

pub enum MemoryRegionKind {
    Usable,
    Reserved,
    AcpiReclaimable,
    AcpiNvs,
    Defective,
    BootloaderReclaimable,
    KernelImage,
}

pub struct FramebufferInfo {
    pub addr: u64,
    pub width: u32,
    pub height: u32,
    pub bpp: u32,
    pub pitch: u32,
}
```

Multiboot2 header is defined in `oncrix-kernel` (`arch/x86_64/multiboot2.rs`)
and placed in the `.multiboot2` section by the linker script.

---

## oncrix-mm

**Path**: `crates/mm/src/`
**Role**: Memory management — physical allocation, virtual memory, kernel heap.
**Dependencies**: `oncrix-lib`, `oncrix-hal`

### Address Types (`addr.rs`)

```rust
pub struct PhysAddr(u64);  // Masked to 52 bits (x86_64 physical)
pub struct VirtAddr(u64);  // Canonical form (sign-extended from bit 47)
```

**Constants**: `PAGE_SIZE = 4096`, `PAGE_SHIFT = 12`.

**VirtAddr methods**:
- `p4_index()` → bits [47:39] (PML4 index)
- `p3_index()` → bits [38:30] (PDPT index)
- `p2_index()` → bits [29:21] (PD index)
- `p1_index()` → bits [20:12] (PT index)
- `page_offset()` → bits [11:0]
- `is_page_aligned()`, `align_down()`, `align_up()`

### Frame & Page (`frame.rs`)

```rust
pub struct Frame { frame_number: u64 }  // frame_number = phys_addr / 4096
pub struct Page  { page_number: u64 }   // page_number = virt_addr / 4096

pub trait FrameAllocator {
    fn allocate_frame(&mut self) -> Option<Frame>;
    fn deallocate_frame(&mut self, frame: Frame);
    fn free_frames(&self) -> usize;
}
```

### Bitmap Allocator (`bitmap.rs`)

```rust
pub struct BitmapAllocator {
    bitmap: [u64; 512],     // 512 × 64 = 32,768 frames = 128 MiB
    total_frames: usize,    // Actual frame count
    free_count: usize,      // Free frame count
}
```

**Operations**:
- `mark_range_free(start_frame, count)` — clears bits
- `mark_range_used(start_frame, count)` — sets bits
- `allocate()` → scans for first zero bit, sets it, returns `Frame`
- `deallocate(frame)` → clears the bit

### Page Table (`page_table.rs`)

```rust
pub struct PageTable {
    entries: [PageTableEntry; 512],  // 4 KiB aligned
}

pub struct PageTableEntry(u64);
```

**Flag constants**:

```rust
pub const PRESENT:       u64 = 1 << 0;
pub const WRITABLE:      u64 = 1 << 1;
pub const USER:          u64 = 1 << 2;
pub const WRITE_THROUGH: u64 = 1 << 3;
pub const NO_CACHE:      u64 = 1 << 4;
pub const ACCESSED:      u64 = 1 << 5;
pub const DIRTY:         u64 = 1 << 6;
pub const HUGE_PAGE:     u64 = 1 << 7;
pub const GLOBAL:        u64 = 1 << 8;
pub const NO_EXECUTE:    u64 = 1 << 63;
```

**Functions**:
- `map_page(page, frame, flags)` — walks/creates 4 levels, sets entry
- `unmap_page(page)` — clears the PTE, flushes TLB
- `flush_tlb_page(addr)` — `invlpg` instruction
- `flush_tlb_all()` — reload CR3

### Heap Allocator (`heap.rs`)

```rust
pub struct LinkedListAllocator {
    head: *mut FreeBlock,
    heap_start: usize,
    heap_size: usize,
}

struct FreeBlock {
    size: usize,
    next: *mut FreeBlock,
}
```

Implements `GlobalAlloc` (`alloc`/`dealloc`).

**Algorithm**: First-fit with splitting. On dealloc, block is inserted at list
head (future: coalescing adjacent free blocks).

### Address Space (`address_space.rs`)

```rust
pub struct AddressSpace {
    pml4_phys: PhysAddr,
    regions: [Option<VmRegion>; 64],  // MAX_REGIONS = 64
    region_count: usize,
}
```

**Boundary constants**:
- `USER_SPACE_START = 0x0000_0000_0040_0000`
- `USER_SPACE_END   = 0x0000_7FFF_FFFF_FFFF`
- `KERNEL_SPACE_START = 0xFFFF_8000_0000_0000`

**Operations**:
- `create_user_space()` — allocates PML4 frame
- `add_region(region)` — overlap detection via linear scan
- `find_region(addr)` — returns region containing `addr`
- `remove_region(start)` — removes by start address

---

## oncrix-ipc

**Path**: `crates/ipc/src/`
**Role**: IPC primitives — the microkernel's core communication mechanism.
**Dependencies**: `oncrix-lib`

### Message (`message.rs`)

```rust
pub const MAX_INLINE_PAYLOAD: usize = 256;

pub struct EndpointId(pub u64);

pub struct MessageHeader {
    pub sender: EndpointId,
    pub receiver: EndpointId,
    pub tag: u32,
    pub payload_len: u32,
}

pub struct Message {
    header: MessageHeader,
    payload: [u8; MAX_INLINE_PAYLOAD],
}
```

**Methods**: `new(sender, receiver, tag)`, `set_payload(&[u8])`,
`payload() → &[u8]` (sliced to `payload_len`), `tag() → u32`.

### Endpoint (`endpoint.rs`)

```rust
pub enum EndpointState { Idle, Sending, Receiving }

pub struct Endpoint {
    pub id: EndpointId,
    pub state: EndpointState,
}

pub trait SyncIpc {
    fn send(&mut self, msg: &Message) -> Result<()>;
    fn receive(&mut self) -> Result<Message>;
    fn reply(&mut self, msg: &Message) -> Result<()>;
    fn call(&mut self, request: &Message) -> Result<Message>;
}
```

### Channel (`channel.rs`)

```rust
pub const CHANNEL_CAPACITY: usize = 16;

pub struct MessageSlot {
    pub occupied: bool,
    pub sender: EndpointId,
    pub tag: u32,
    pub payload_len: u32,
    pub payload: [u8; MAX_INLINE_PAYLOAD],
}

pub struct Channel {
    src: EndpointId,
    dst: EndpointId,
    buffer: [MessageSlot; CHANNEL_CAPACITY],
    head: usize,
    tail: usize,
    count: usize,
}
```

**Operations**:
- `send(msg)` → writes to `buffer[tail]`, advances `tail`, increments `count`
- `receive()` → reads from `buffer[head]`, advances `head`, decrements `count`
- Returns `WouldBlock` when full (send) or empty (receive)

### Channel Registry

```rust
pub struct ChannelRegistry {
    channels: [Option<Channel>; 64],  // MAX_CHANNELS = 64
    count: usize,
}
```

**Operations**: `create(src, dst)`, `find(src, dst)`, `remove(id)`.

---

## oncrix-process

**Path**: `crates/process/src/`
**Role**: Process and thread lifecycle management.
**Dependencies**: `oncrix-lib`

### PID/TID (`pid.rs`)

```rust
pub struct Pid(u64);
pub struct Tid(u64);

pub const KERNEL_PID: Pid = Pid(0);
```

`alloc_pid()` / `alloc_tid()`: atomic `fetch_add` on global counters.

### Process (`process.rs`)

```rust
pub enum ProcessState { Active, Exited }

pub struct Process {
    pid: Pid,
    state: ProcessState,
    threads: [Option<Tid>; 64],  // MAX_THREADS_PER_PROCESS = 64
    thread_count: usize,
}
```

**Methods**: `new(pid)`, `add_thread(tid)`, `remove_thread(tid)`,
`thread_count()`, `pid()`, `state()`, `set_state()`.

### Thread (`thread.rs`)

```rust
pub enum ThreadState { Ready, Running, Blocked, Exited }

pub struct Priority(u8);

impl Priority {
    pub const HIGHEST: Self = Self(0);
    pub const NORMAL: Self = Self(128);
    pub const IDLE: Self = Self(255);
}

pub struct Thread {
    tid: Tid,
    pid: Pid,
    state: ThreadState,
    priority: Priority,
    stack_pointer: u64,
}
```

### Scheduler (`scheduler.rs`)

```rust
pub struct RoundRobinScheduler {
    threads: [Option<Thread>; 256],  // Max 256 threads
    current: Option<usize>,          // Currently running slot
    cursor: usize,                   // Round-robin position
    count: usize,
}
```

**Operations**:
- `add(thread)` → first empty slot
- `remove(tid)` → finds and removes
- `schedule()` → scans from cursor for next `Ready` thread, marks `Running`
- `block_current()` → marks current as `Blocked`
- `unblock(tid)` → finds thread, marks `Ready`

### Fork (`fork.rs`)

See [ARCHITECTURE.md — Fork](ARCHITECTURE.md#fork) for design details.

```rust
pub struct ForkResult {
    pub child_pid: Pid,
    pub child_tid: Tid,
}

pub fn fork_process(
    parent: &Process,
    parent_priority: Priority,
) -> Result<(ForkResult, Process, Thread)>;
```

**CowTracker**: 4096-frame array, `share()`/`unshare()` with refcounting.
See architecture doc for state machine.

### Signal Handling (`signal.rs`)

```rust
pub struct Signal(u8);

// POSIX constants
pub const SIGHUP: Signal  = Signal(1);
pub const SIGINT: Signal  = Signal(2);
// ... up to SIGTSTP(20), Signal::MAX = 32

pub enum SignalAction {
    Default,
    Ignore,
    Handler(u64),  // User-space handler address
}

pub struct SignalMask(u32);    // Bitset of blocked signals
pub struct PendingSignals(u32); // Bitset of pending signals

pub struct SignalState {
    actions: [SignalAction; 32],
    mask: SignalMask,
    pending: PendingSignals,
}
```

**Methods**: `SignalMask::block(signal)`, `unblock(signal)`, `is_blocked(signal)`.
`PendingSignals::raise(signal)`, `clear(signal)`, `next_pending(mask)`.

---

## oncrix-vfs

**Path**: `crates/vfs/src/`
**Role**: Virtual File System — unified abstraction over multiple filesystems.
**Dependencies**: `oncrix-lib`

### Inode (`inode.rs`)

```rust
pub struct InodeNumber(u64);

pub enum FileType {
    Regular, Directory, Symlink,
    CharDevice, BlockDevice, Fifo, Socket,
}

pub struct FileMode(u16);  // POSIX permission bits

impl FileMode {
    pub const OWNER_READ:  Self = Self(0o400);
    pub const OWNER_WRITE: Self = Self(0o200);
    pub const OWNER_EXEC:  Self = Self(0o100);
    pub const OWNER_RWX:   Self = Self(0o700);
    pub const GROUP_RWX:   Self = Self(0o070);
    pub const OTHER_RWX:   Self = Self(0o007);
    pub const DEFAULT_FILE: Self = Self(0o644);
    pub const DEFAULT_DIR:  Self = Self(0o755);
}

pub struct Inode {
    pub ino: InodeNumber,
    pub file_type: FileType,
    pub mode: FileMode,
    pub size: u64,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
}
```

**InodeOps trait**: `lookup`, `create`, `mkdir`, `unlink`, `rmdir`, `read`,
`write`, `truncate` — see [ARCHITECTURE.md](ARCHITECTURE.md#core-types).

### Dentry Cache (`dentry.rs`)

```rust
pub struct DentryName {
    bytes: [u8; 255],  // File/dir name
    len: u8,
}

pub struct Dentry {
    pub name: DentryName,
    pub inode: InodeNumber,
    pub parent: InodeNumber,
}

pub struct DentryCache {
    entries: [Option<Dentry>; 256],  // 256-entry linear cache
    count: usize,
}
```

**Operations**: `insert(dentry)`, `lookup(parent, name)`, `remove(parent, name)`.

### Superblock & Mount (`superblock.rs`)

```rust
pub enum FsType { Ramfs, DevFs, ProcFs }

pub struct Superblock {
    pub fs_type: FsType,
    pub root: InodeNumber,
    pub block_size: u32,
    pub max_name_len: u32,
    pub read_only: bool,
}

pub struct MountPath {
    bytes: [u8; 256],
    len: usize,
}

pub struct MountEntry {
    pub path: MountPath,
    pub superblock: Superblock,
}

pub struct MountTable {
    mounts: [Option<MountEntry>; 16],  // MAX_MOUNTS = 16
    count: usize,
}
```

### File Descriptors (`file.rs`)

```rust
pub struct Fd(u32);

impl Fd {
    pub const STDIN:  Self = Self(0);
    pub const STDOUT: Self = Self(1);
    pub const STDERR: Self = Self(2);
}

pub struct OpenFlags(u32);
// O_RDONLY=0, O_WRONLY=1, O_RDWR=2, O_CREAT=0o100, O_TRUNC=0o1000, O_APPEND=0o2000

pub struct OpenFile {
    pub inode: InodeNumber,
    pub offset: u64,
    pub flags: OpenFlags,
}

pub struct FdTable {
    files: [Option<OpenFile>; 256],  // MAX_OPEN_FILES = 256
    count: usize,
}
```

**Methods**: `alloc(file) → Result<Fd>`, `get(fd)`, `get_mut(fd)`,
`close(fd)`, `dup2(old_fd, new_fd)`.

### ramfs (`ramfs.rs`)

```rust
pub struct RamFs {
    inodes: [Option<RamInode>; 128],  // MAX_INODES = 128
    inode_count: usize,
    next_ino: u64,
}

enum RamInodeData {
    File {
        data: [u8; 4096],  // MAX_FILE_SIZE = 4096
        len: usize,
    },
    Dir {
        entries: [Option<RamDirEntry>; 32],  // MAX_DIR_ENTRIES = 32
        count: usize,
    },
}

struct RamDirEntry {
    name: [u8; 256],
    name_len: usize,
    inode: InodeNumber,
}
```

Implements all `InodeOps` methods. Root inode (ino=1) is always a directory.

### devfs (`devfs.rs`)

64 device nodes. Each node stores: name, inode number, device type (Char/Block),
major/minor numbers. Supports register/unregister/lookup.

### procfs (`procfs.rs`)

Generated-on-read filesystem. Each virtual file returns a dynamically
constructed byte buffer:
- `version` → `"ONCRIX 0.1.0\n"`
- `uptime` → tick count formatted as seconds
- `meminfo` → total/free/used frame counts
- `cpuinfo` → architecture and feature string

### Pipe (`pipe.rs`)

```rust
pub struct Pipe {
    buffer: [u8; 4096],  // PIPE_BUF_SIZE = 4096
    read_pos: usize,
    write_pos: usize,
    count: usize,
    read_open: bool,
    write_open: bool,
}

pub struct PipeId(usize);

pub struct PipeRegistry {
    pipes: [Option<Pipe>; 64],  // MAX_PIPES = 64
    count: usize,
}
```

**Semantics**: see [ARCHITECTURE.md — Pipe](ARCHITECTURE.md#pipe).

### Path Resolution (`path.rs`)

```rust
pub fn split_path(path: &[u8]) -> ([([u8; 256], usize); 64], usize);
pub fn resolve_path(...) -> Result<InodeNumber>;
pub fn vfs_open(path, flags, mode, ...) -> Result<InodeNumber>;
pub fn vfs_open_fd(fd_table, inode, flags) -> Result<Fd>;
```

### VFS Operations (`ops.rs`)

```rust
pub fn vfs_read(fd_table, fd, buf, fs, inode_lookup) -> Result<usize>;
pub fn vfs_write(fd_table, fd, data, fs, inode_lookup) -> Result<usize>;
pub fn vfs_lseek(fd_table, fd, offset, whence, inode_lookup) -> Result<u64>;
pub fn vfs_stat(inode) -> Result<StatInfo>;
```

`StatInfo`: `st_ino`, `st_mode` (type bits | permission bits), `st_nlink`,
`st_size`, `st_uid`, `st_gid`.

---

## oncrix-drivers

**Path**: `crates/drivers/src/`
**Role**: User-space device driver framework.
**Dependencies**: `oncrix-lib`

### Device (`device.rs`)

```rust
pub struct DeviceId(u32);

pub enum DeviceClass {
    Block, Char, Network, Display, Input, Other,
}

pub enum DeviceStatus {
    Uninitialized, Ready, Busy, Error, Removed,
}

pub struct DeviceInfo {
    pub id: DeviceId,
    pub class: DeviceClass,
    pub name: [u8; 64],
    pub name_len: usize,
    pub irq: Option<u8>,
    pub status: DeviceStatus,
}

pub trait Driver {
    fn init(&mut self) -> Result<()>;
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<usize>;
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<usize>;
    fn handle_irq(&mut self) -> Result<()>;
    fn shutdown(&mut self) -> Result<()>;
}
```

### Registry (`registry.rs`)

```rust
pub struct DeviceRegistry {
    devices: [Option<DeviceInfo>; 64],  // MAX_DEVICES = 64
    count: usize,
}
```

**Operations**: `register(info)`, `unregister(id)`, `find_by_id(id)`,
`find_by_class(class)`, `find_by_irq(irq)`, `set_status(id, status)`.

---

## oncrix-syscall

**Path**: `crates/syscall/src/`
**Role**: POSIX-compatible system call interface.
**Dependencies**: `oncrix-lib`

### Numbers (`number.rs`)

Full table at [ARCHITECTURE.md — Syscall Table](ARCHITECTURE.md#syscall-table).
ONCRIX-specific IPC extensions start at 512.

### Dispatcher (`dispatch.rs`)

```rust
#[repr(C)]
pub struct SyscallArgs {
    pub number: u64,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    pub arg5: u64,
}

pub fn dispatch(args: &SyscallArgs) -> i64;
```

Maps `args.number` to the appropriate handler via `match`. Unknown numbers
return `-38` (ENOSYS).

### Handlers (`handler.rs`)

22 handler stubs. Each validates arguments and returns `SyscallResult = i64`.

```rust
pub fn error_to_errno(err: Error) -> i64;  // Maps Error → negative errno

#[repr(C)]
pub struct StatBuf {
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_size: u64,
}
```

Implemented handlers: `sys_read`, `sys_write`, `sys_open`, `sys_close`,
`sys_stat`, `sys_fstat`, `sys_lseek`, `sys_mmap`, `sys_munmap`, `sys_brk`,
`sys_getpid`, `sys_fork`, `sys_execve`, `sys_exit`, `sys_wait4`, `sys_kill`,
`sys_pipe`, `sys_dup2`, `sys_mkdir`, `sys_rmdir`, `sys_unlink`,
`sys_rt_sigaction`.

---

## oncrix-kernel

**Path**: `crates/kernel/src/`
**Role**: Microkernel integration crate — ties all components together.
**Dependencies**: All other crates.

### Entry Point (`main.rs`)

```rust
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    kernel_main();
}

fn kernel_main() -> ! {
    // Phase 1-7 initialization (see Boot Sequence in ARCHITECTURE.md)
    halt_loop();
}
```

`#[panic_handler]` prints to serial and halts.

### ELF Loader (`elf.rs`)

```rust
#[repr(C)]
pub struct Elf64Header {
    pub e_ident: [u8; 16],    // Magic + class + endian + version
    pub e_type: u16,          // ET_EXEC=2, ET_DYN=3
    pub e_machine: u16,       // EM_X86_64=62
    pub e_version: u32,
    pub e_entry: u64,         // Entry point virtual address
    pub e_phoff: u64,         // Program header table offset
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,         // Number of program headers
    // ...
}

#[repr(C)]
pub struct Elf64Phdr {
    pub p_type: u32,          // PT_LOAD=1
    pub p_flags: u32,         // PF_X=1, PF_W=2, PF_R=4
    pub p_offset: u64,        // Offset in file
    pub p_vaddr: u64,         // Virtual address
    pub p_paddr: u64,
    pub p_filesz: u64,        // Size in file
    pub p_memsz: u64,         // Size in memory (≥ filesz for BSS)
    pub p_align: u64,
}
```

**Functions**: `parse_header(data) → Result<ElfInfo>`,
`load_segments(data, header) → Result<Vec<LoadedSegment>>`.

### Exec (`exec.rs`)

```rust
pub const USER_STACK_SIZE: usize = 65536;  // 64 KiB
pub const MAX_ELF_SIZE: usize = 16 * 1024 * 1024;  // 16 MiB

pub struct ExecInfo {
    pub entry: u64,
    pub stack_top: u64,
    pub pid: Pid,
    pub is_pie: bool,
    pub region_count: usize,
}

pub fn prepare_exec(elf_data: &[u8]) -> Result<ExecInfo>;
pub fn create_user_thread(pid: Pid, priority: Priority) -> Result<Thread>;
```

**`prepare_exec` flow**:
1. `parse_header` → validate ELF64, x86_64, get entry + segments
2. `create_user_space()` → allocate PML4
3. For each PT_LOAD → `segment_protection()` + `segment_kind()` → `VmRegion`
4. Add stack region: `USER_SPACE_END - 0xFFF - USER_STACK_SIZE`
5. `compute_initial_brk()` → page-aligned end of highest segment

### User Access (`uaccess.rs`)

```rust
pub fn validate_user_range(ptr: u64, len: usize) -> Result<()>;
pub unsafe fn copy_from_user(dst: *mut u8, src: u64, len: usize) -> Result<()>;
pub unsafe fn copy_to_user(dst: u64, src: *const u8, len: usize) -> Result<()>;
pub fn validate_user_string(ptr: u64, max_len: usize) -> Result<usize>;
pub unsafe fn get_user_u64(addr: u64) -> Result<u64>;
pub unsafe fn put_user_u64(addr: u64, value: u64) -> Result<()>;
```

### Preemptive Scheduler (`sched.rs`)

```rust
pub const DEFAULT_SLICE: u32 = 10;
pub const MIN_SLICE: u32 = 1;
pub const MAX_SLICE: u32 = 50;

pub struct PreemptionState { /* see ARCHITECTURE.md */ }
```

**Functions**: `timer_tick() → bool`, `reset_slice(priority)`,
`disable()`, `enable() → bool`, `yield_now()`.

### x86_64 Architecture (`arch/x86_64/`)

| File | Content |
|------|---------|
| `init.rs` | GDT/IDT/heap/scheduler/PIC+PIT initialization |
| `exceptions.rs` | 5 exception handlers (#DE, #UD, #DF, #GP, #PF) |
| `interrupts.rs` | Timer (IRQ 0), keyboard (IRQ 1), spurious (IRQ 7) |
| `context.rs` | `CpuContext`, `switch_context` assembly |
| `syscall_entry.rs` | SYSCALL/SYSRET MSR setup, entry/exit assembly stub |
| `usermode.rs` | `jump_to_usermode` via `iretq` |
| `kthread.rs` | Thread pool (32 threads, 8 KiB stacks) |
| `multiboot2.rs` | Multiboot2 header in `.multiboot2` section |

---

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

**Rules**:
- No `unwrap()` or `expect()` in production paths
- Use `?` for propagation
- Wrap `Option` → `Result` with `ok_or(Error::...)`
- Syscall layer converts `Error` → negative errno via `error_to_errno()`

---

## Testing Strategy

| Level | Method | Location |
|-------|--------|----------|
| Unit | `#[cfg(test)]` modules | Per-file `mod tests` |
| Integration | Cross-crate tests | `tests/` directories |
| Architecture | Conditional compilation | `#[cfg(target_arch = "...")]` |
| System | Full boot in QEMU | `scripts/run-qemu.sh` |

---

## Build & CI

### Requirements

- Rust 1.85+ (nightly for `#![no_std]` features)
- QEMU 7.0+ (for system testing)
- `rust-src` component (`rustup component add rust-src`)

### Verification Command

```bash
cargo fmt --all -- --check && cargo clippy --workspace -- -D warnings && cargo build --workspace
```

### CI Pipeline (GitHub Actions)

1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace -- -D warnings`
3. `cargo build --workspace`

---

## Glossary

| Term | Definition |
|------|-----------|
| **APIC** | Advanced Programmable Interrupt Controller — x86 interrupt hardware |
| **Capability** | Unforgeable token granting specific access rights to a resource |
| **CoW** | Copy-on-Write — deferred page duplication after fork |
| **DMA** | Direct Memory Access — hardware-initiated memory transfers |
| **ELF** | Executable and Linkable Format — standard executable format |
| **GDT** | Global Descriptor Table — x86 segment descriptor table |
| **HAL** | Hardware Abstraction Layer — platform-independent hardware interface |
| **IDT** | Interrupt Descriptor Table — x86 interrupt handler registration |
| **IPC** | Inter-Process Communication — message passing between processes |
| **IST** | Interrupt Stack Table — per-vector stack switching (x86_64) |
| **MADT** | Multiple APIC Description Table — ACPI table for interrupt controllers |
| **MMU** | Memory Management Unit — hardware virtual-to-physical translation |
| **PIT** | Programmable Interval Timer — legacy 8254 timer chip |
| **POSIX** | Portable Operating System Interface — Unix API standard |
| **RSDP** | Root System Description Pointer — ACPI entry point structure |
| **TCB** | Trusted Computing Base — minimal code that must be correct for security |
| **TLB** | Translation Lookaside Buffer — MMU cache for page table entries |
| **TSS** | Task State Segment — x86 privilege-level stack storage |
| **UEFI** | Unified Extensible Firmware Interface — modern boot protocol |
| **VFS** | Virtual File System — unified file system abstraction |
| **XSDT** | Extended System Description Table — ACPI table index (64-bit) |
