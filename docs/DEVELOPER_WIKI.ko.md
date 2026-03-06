# ONCRIX 개발자 위키

[English](DEVELOPER_WIKI.md)

ONCRIX 크레이트별 구현 레퍼런스입니다.
아키텍처 개요와 설계 철학은 [ARCHITECTURE.ko.md](ARCHITECTURE.ko.md)를 참고하세요.

---

## 목차

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
11. [에러 처리 패턴](#에러-처리-패턴)
12. [테스트 전략](#테스트-전략)
13. [빌드 & CI](#빌드--ci)
14. [용어집](#용어집)

---

## oncrix-lib

**경로**: `crates/lib/src/lib.rs`
**역할**: 모든 크레이트가 공유하는 기초 타입.
**의존성**: 없음 (`core`만).

### Error 열거형

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

`Display` (사람 읽기용), `Debug` (Rust 형식) 구현.

### Result 타입

```rust
pub type Result<T> = core::result::Result<T, Error>;
```

커널 전반의 모든 실패 가능 연산이 이 타입을 반환.
전파에는 `?` 사용 — 프로덕션 경로에서 `unwrap()`/`expect()` 금지.

---

## oncrix-hal

**경로**: `crates/hal/src/`
**역할**: 하드웨어 추상화 계층 — 모든 아키텍처별 코드가 여기에 위치.
**의존성**: `oncrix-lib`

### 트레이트 정의

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

`InterruptVector`는 `u8` 뉴타입.

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

### x86_64 구현

#### UART 16550 (`arch/x86_64/uart.rs`)

| 포트 | COM1 기본 | COM2 기본 |
|------|-----------|-----------|
| Data (THR/RBR) | 0x3F8 + 0 | 0x2F8 + 0 |
| IER | +1 | +1 |
| FCR | +2 | +2 |
| LCR | +3 | +3 |
| MCR | +4 | +4 |
| LSR | +5 | +5 |
| DLL (DLAB=1) | +0 | +0 |
| DLH (DLAB=1) | +1 | +1 |

**초기화 순서** (115200 baud, 8N1):
1. 인터럽트 비활성화 (`IER = 0`)
2. DLAB 설정 (`LCR |= 0x80`), 디바이저 1 (`DLL = 1, DLH = 0`)
3. DLAB 해제, 8N1 설정 (`LCR = 0x03`)
4. FIFO 활성화 (`FCR = 0xC7`)
5. DTR + RTS + OUT2 설정 (`MCR = 0x0B`)

**LSR 플래그**: `DATA_READY = 0x01`, `TX_EMPTY = 0x20`.

포트 I/O는 `io.rs`의 인라인 어셈블리 `inb`/`outb` 사용.

#### GDT (`arch/x86_64/gdt.rs`)

**세그먼트 배치** (7 엔트리, TSS에 2개):

| 인덱스 | 셀렉터 | 타입 | DPL |
|--------|--------|------|-----|
| 0 | 0x00 | Null | — |
| 1 | 0x08 | Kernel Code (64비트, long mode) | 0 |
| 2 | 0x10 | Kernel Data | 0 |
| 3 | 0x18 | User Data | 3 |
| 4 | 0x20 | User Code (64비트, long mode) | 3 |
| 5-6 | 0x28 | TSS (16바이트, GDT 2슬롯) | 0 |

**참고**: 유저 셀렉터는 RPL=3 비트 포함: `USER_DATA = 0x1B`, `USER_CODE = 0x23`.

**TSS** (104바이트): `privilege_stacks[3]` (RSP0-2), `ist[7]` (IST1-7).
더블 폴트 핸들러는 전용 16 KiB 스택의 IST1 사용.

#### IDT (`arch/x86_64/idt.rs`)

256 엔트리, 각 16바이트:

```rust
pub struct IdtEntry {
    offset_low: u16,       // 핸들러 주소 [15:0]
    segment_selector: u16, // 코드 세그먼트 (0x08)
    ist: u8,               // IST 인덱스 (0 = IST 미사용)
    type_attr: u8,         // 게이트 타입 + DPL + Present
    offset_mid: u16,       // 핸들러 주소 [31:16]
    offset_high: u32,      // 핸들러 주소 [63:32]
    reserved: u32,
}
```

게이트 타입: `INTERRUPT = 0x8E` (IF 클리어), `TRAP = 0x8F` (IF 유지).

#### 8259 PIC (`arch/x86_64/pic.rs`)

**I/O 포트**:

| PIC | 커맨드 | 데이터 |
|-----|--------|--------|
| 마스터 | 0x20 | 0x21 |
| 슬레이브 | 0xA0 | 0xA1 |

**ICW 시퀀스**:

```
ICW1 = 0x11 (init + ICW4 필요)
ICW2 = 오프셋 (마스터: 32, 슬레이브: 40)
ICW3 = 캐스케이드 (마스터: 0x04 = IRQ2, 슬레이브: 0x02)
ICW4 = 0x01 (8086 모드)
```

**연산**: `mask(irq)`, `unmask(irq)`, `send_eoi(irq)`.
슬레이브 IRQ (8-15)는 슬레이브와 마스터 둘 다에 EOI 전송.

#### PIT 8254 (`arch/x86_64/pit.rs`)

| 상수 | 값 |
|------|-----|
| 기본 주파수 | 1,193,182 Hz |
| 디바이저 (~100 Hz) | 11,932 |
| 채널 0 포트 | 0x40 |
| 커맨드 포트 | 0x43 |

**모드**: `RATE_GEN = 0x34` (모드 2, 주기적), `ONESHOT = 0x30` (모드 0).

#### Local APIC 타이머 (`arch/x86_64/apic.rs`)

**MMIO 레지스터** (기본 `0xFEE0_0000`):

| 이름 | 오프셋 | 접근 |
|------|--------|------|
| APIC ID | 0x020 | R |
| Version | 0x030 | R |
| TPR | 0x080 | R/W |
| EOI | 0x0B0 | W |
| SIVR | 0x0F0 | R/W |
| LVT Timer | 0x320 | R/W |
| Initial Count | 0x380 | R/W |
| Current Count | 0x390 | R |
| Divide Config | 0x3E0 | R/W |

**TimerDivide 값**: `By1=0b1011`, `By2=0b0000`, `By4=0b0001`,
`By8=0b0010`, `By16=0b0011`, `By32=0b1000`, `By64=0b1001`, `By128=0b1010`.

**캘리브레이션** (`calibrate_with_pit()`):
1. 분주를 `By16`으로, 초기 카운트를 `0xFFFF_FFFF`로 설정
2. `pit_sleep_10ms()` — PIT 채널 2 스피커 게이트 사용
3. APIC 현재 카운트 읽기 → elapsed = `0xFFFF_FFFF - current`
4. `frequency_hz = elapsed * 100 * 16`

### ACPI (`acpi.rs`)

**RSDP 구조체** (`repr(C, packed)`):

```rust
pub struct RsdpDescriptor {
    signature: [u8; 8],      // "RSD PTR "
    checksum: u8,            // 첫 20바이트 합 = 0
    oem_id: [u8; 6],
    revision: u8,            // 0 = ACPI 1.0, 2 = ACPI 2.0+
    rsdt_address: u32,
}
```

**`find_rsdp()`**: `0xE0000`–`0xFFFFF`에서 16바이트 경계로 `"RSD PTR "` 탐색.

**XSDT**: 헤더 (36바이트) + `u64` 주소 배열 (최대 32개).

**MADT** (`"APIC"` 시그니처):
- 오프셋 36: `local_apic_address: u32`
- 오프셋 44부터 가변 길이 엔트리:

| 타입 | 길이 | 내용 |
|------|------|------|
| 0 | 8 | Local APIC: processor_id, apic_id, flags |
| 1 | 12 | I/O APIC: id, address, gsi_base |
| 2 | 10 | Int Source Override: bus, source, gsi, flags |

**한계**: Local APIC 64개, I/O APIC 8개, Override 16개.

모든 ACPI 구조체는 `repr(C, packed)`로 인해 `read_unaligned()` 사용.

---

## oncrix-bootloader

**경로**: `crates/bootloader/src/`
**역할**: 부트 프로토콜 구조체 및 커널 핸드오프.
**의존성**: `oncrix-lib`

### 주요 구조체

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

pub enum MemoryRegionKind {
    Usable, Reserved, AcpiReclaimable,
    AcpiNvs, Defective, BootloaderReclaimable, KernelImage,
}

pub struct FramebufferInfo {
    pub addr: u64, pub width: u32, pub height: u32,
    pub bpp: u32, pub pitch: u32,
}
```

---

## oncrix-mm

**경로**: `crates/mm/src/`
**역할**: 메모리 관리 — 물리 할당, 가상 메모리, 커널 힙.
**의존성**: `oncrix-lib`, `oncrix-hal`

### 주소 타입 (`addr.rs`)

```rust
pub struct PhysAddr(u64);  // 52비트 마스크 (x86_64 물리)
pub struct VirtAddr(u64);  // 정규 형태 (비트 47에서 부호 확장)
```

**상수**: `PAGE_SIZE = 4096`, `PAGE_SHIFT = 12`.

**VirtAddr 메서드**: `p4_index()` [47:39], `p3_index()` [38:30],
`p2_index()` [29:21], `p1_index()` [20:12], `page_offset()` [11:0],
`is_page_aligned()`, `align_down()`, `align_up()`.

### 프레임 & 페이지 (`frame.rs`)

```rust
pub struct Frame { frame_number: u64 }  // = phys_addr / 4096
pub struct Page  { page_number: u64 }   // = virt_addr / 4096

pub trait FrameAllocator {
    fn allocate_frame(&mut self) -> Option<Frame>;
    fn deallocate_frame(&mut self, frame: Frame);
    fn free_frames(&self) -> usize;
}
```

### 비트맵 할당기 (`bitmap.rs`)

```rust
pub struct BitmapAllocator {
    bitmap: [u64; 512],     // 512 × 64 = 32,768 프레임 = 128 MiB
    total_frames: usize,
    free_count: usize,
}
```

**연산**: `mark_range_free(start, count)`, `mark_range_used(start, count)`,
`allocate()` (first-fit), `deallocate(frame)`.

### 페이지 테이블 (`page_table.rs`)

```rust
pub struct PageTable { entries: [PageTableEntry; 512] }  // 4 KiB 정렬
pub struct PageTableEntry(u64);
```

**플래그**: `PRESENT=1<<0`, `WRITABLE=1<<1`, `USER=1<<2`,
`WRITE_THROUGH=1<<3`, `NO_CACHE=1<<4`, `ACCESSED=1<<5`, `DIRTY=1<<6`,
`HUGE_PAGE=1<<7`, `GLOBAL=1<<8`, `NO_EXECUTE=1<<63`.

**함수**: `map_page(page, frame, flags)`, `unmap_page(page)`,
`flush_tlb_page(addr)` (`invlpg`), `flush_tlb_all()` (CR3 리로드).

### 힙 할당기 (`heap.rs`)

```rust
pub struct LinkedListAllocator {
    head: *mut FreeBlock,
    heap_start: usize,
    heap_size: usize,
}
struct FreeBlock { size: usize, next: *mut FreeBlock }
```

`GlobalAlloc` 구현. First-fit + 분할. 해제 시 리스트 헤드에 삽입.

### 주소 공간 (`address_space.rs`)

```rust
pub struct AddressSpace {
    pml4_phys: PhysAddr,
    regions: [Option<VmRegion>; 64],  // MAX_REGIONS = 64
    region_count: usize,
}
```

**경계**: `USER_SPACE_START = 0x0000_0000_0040_0000`,
`USER_SPACE_END = 0x0000_7FFF_FFFF_FFFF`,
`KERNEL_SPACE_START = 0xFFFF_8000_0000_0000`.

**VmRegion**: `start: VirtAddr`, `size: usize`, `prot: Protection` (R/W/X),
`kind: RegionKind` (Code/Data/Heap/Stack/Mmap).

---

## oncrix-ipc

**경로**: `crates/ipc/src/`
**역할**: IPC 프리미티브 — 마이크로커널 핵심 통신 메커니즘.
**의존성**: `oncrix-lib`

### 메시지 (`message.rs`)

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
    payload: [u8; 256],
}
```

### 채널 (`channel.rs`)

```rust
pub const CHANNEL_CAPACITY: usize = 16;

pub struct Channel {
    src: EndpointId, dst: EndpointId,
    buffer: [MessageSlot; 16],
    head: usize, tail: usize, count: usize,
}

pub struct ChannelRegistry {
    channels: [Option<Channel>; 64],  // MAX_CHANNELS = 64
    count: usize,
}
```

**연산**: `send()` → `buffer[tail]`에 쓰기, `receive()` → `buffer[head]`에서 읽기.
가득 찬 경우 `WouldBlock`, 빈 경우 `WouldBlock`.

### SyncIpc 트레이트

```rust
pub trait SyncIpc {
    fn send(&mut self, msg: &Message) -> Result<()>;
    fn receive(&mut self) -> Result<Message>;
    fn reply(&mut self, msg: &Message) -> Result<()>;
    fn call(&mut self, request: &Message) -> Result<Message>;
}
```

---

## oncrix-process

**경로**: `crates/process/src/`
**역할**: 프로세스/스레드 생명주기 관리.
**의존성**: `oncrix-lib`

### PID/TID (`pid.rs`)

```rust
pub struct Pid(u64);  // KERNEL_PID = Pid(0)
pub struct Tid(u64);
```

`alloc_pid()` / `alloc_tid()`: 전역 카운터에 `fetch_add`.

### Process (`process.rs`)

```rust
pub enum ProcessState { Active, Exited }
pub struct Process {
    pid: Pid, state: ProcessState,
    threads: [Option<Tid>; 64],  // MAX_THREADS_PER_PROCESS = 64
    thread_count: usize,
}
```

### Thread (`thread.rs`)

```rust
pub enum ThreadState { Ready, Running, Blocked, Exited }
pub struct Priority(u8);  // HIGHEST=0, NORMAL=128, IDLE=255

pub struct Thread {
    tid: Tid, pid: Pid, state: ThreadState,
    priority: Priority, stack_pointer: u64,
}
```

### 스케줄러 (`scheduler.rs`)

```rust
pub struct RoundRobinScheduler {
    threads: [Option<Thread>; 256],
    current: Option<usize>,
    cursor: usize,
    count: usize,
}
```

**연산**: `add()`, `remove()`, `schedule()` (커서에서 다음 Ready 스캔),
`block_current()`, `unblock(tid)`.

### Fork (`fork.rs`)

설계 상세: [ARCHITECTURE.ko.md — Fork](ARCHITECTURE.ko.md#fork).

```rust
pub fn fork_process(parent: &Process, parent_priority: Priority)
    -> Result<(ForkResult, Process, Thread)>;
```

**CowTracker**: 4096 프레임, `share()`/`unshare()` 참조 카운팅.

### 시그널 (`signal.rs`)

```rust
pub struct Signal(u8);  // SIGHUP=1 ~ SIGTSTP=20, MAX=32
pub enum SignalAction { Default, Ignore, Handler(u64) }
pub struct SignalMask(u32);      // 차단 시그널 비트셋
pub struct PendingSignals(u32);  // 대기 시그널 비트셋
pub struct SignalState {
    actions: [SignalAction; 32],
    mask: SignalMask,
    pending: PendingSignals,
}
```

---

## oncrix-vfs

**경로**: `crates/vfs/src/`
**역할**: 가상 파일 시스템 — 복수 파일시스템에 대한 통합 추상화.
**의존성**: `oncrix-lib`

### Inode (`inode.rs`)

```rust
pub struct InodeNumber(u64);
pub enum FileType {
    Regular, Directory, Symlink,
    CharDevice, BlockDevice, Fifo, Socket,
}
pub struct FileMode(u16);  // DEFAULT_FILE=0o644, DEFAULT_DIR=0o755
pub struct Inode {
    pub ino: InodeNumber, pub file_type: FileType,
    pub mode: FileMode, pub size: u64,
    pub nlink: u32, pub uid: u32, pub gid: u32,
}
```

**InodeOps 트레이트**: `lookup`, `create`, `mkdir`, `unlink`, `rmdir`,
`read`, `write`, `truncate`.

### Dentry 캐시 (`dentry.rs`)

```rust
pub struct DentryCache {
    entries: [Option<Dentry>; 256],  // 256 엔트리 선형 캐시
    count: usize,
}
```

### 마운트 (`superblock.rs`)

```rust
pub enum FsType { Ramfs, DevFs, ProcFs }
pub struct MountTable {
    mounts: [Option<MountEntry>; 16],  // MAX_MOUNTS = 16
    count: usize,
}
```

### 파일 디스크립터 (`file.rs`)

```rust
pub struct Fd(u32);  // STDIN=0, STDOUT=1, STDERR=2
pub struct OpenFlags(u32);
// O_RDONLY=0, O_WRONLY=1, O_RDWR=2, O_CREAT=0o100, O_TRUNC=0o1000, O_APPEND=0o2000
pub struct FdTable {
    files: [Option<OpenFile>; 256],  // MAX_OPEN_FILES = 256
    count: usize,
}
```

### ramfs (`ramfs.rs`)

| 속성 | 값 |
|------|-----|
| 최대 inode | 128 |
| 최대 파일 크기 | 4,096 바이트 |
| 디렉토리당 최대 엔트리 | 32 |
| 이름 길이 | 255 바이트 |

전체 `InodeOps` 구현. 루트 inode (ino=1)는 항상 디렉토리.

### devfs, procfs

**devfs**: 64 디바이스 노드, Char/Block 등록/해제/조회.
**procfs**: `version`, `uptime`, `meminfo`, `cpuinfo` — 읽기 시 동적 생성.

### 파이프 (`pipe.rs`)

```rust
pub struct Pipe {
    buffer: [u8; 4096],
    read_pos: usize, write_pos: usize, count: usize,
    read_open: bool, write_open: bool,
}
pub struct PipeRegistry { pipes: [Option<Pipe>; 64], count: usize }
```

POSIX 시맨틱: write 닫히면 EOF, read 닫히면 EPIPE.

### 경로 해석 (`path.rs`)

`resolve_path()`: `/`로 분할 → 루트에서 시작 → 컴포넌트마다 `lookup()` →
디렉토리 확인 → 최종 inode 반환.

`vfs_open()`: 경로 해석 + `O_CREAT` (없으면 생성) + `O_TRUNC` (0으로 절삭).

### VFS 연산 (`ops.rs`)

`vfs_read`, `vfs_write`, `vfs_lseek` (SEEK_SET/CUR/END), `vfs_stat` (POSIX st_mode 인코딩).

---

## oncrix-drivers

**경로**: `crates/drivers/src/`
**역할**: 유저 스페이스 디바이스 드라이버 프레임워크.
**의존성**: `oncrix-lib`

```rust
pub enum DeviceClass { Block, Char, Network, Display, Input, Other }
pub enum DeviceStatus { Uninitialized, Ready, Busy, Error, Removed }

pub trait Driver {
    fn init(&mut self) -> Result<()>;
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<usize>;
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<usize>;
    fn handle_irq(&mut self) -> Result<()>;
    fn shutdown(&mut self) -> Result<()>;
}

pub struct DeviceRegistry {
    devices: [Option<DeviceInfo>; 64],  // MAX_DEVICES = 64
    count: usize,
}
```

**연산**: `register`, `unregister`, `find_by_id`, `find_by_class`, `find_by_irq`.

---

## oncrix-syscall

**경로**: `crates/syscall/src/`
**역할**: POSIX 호환 시스콜 인터페이스.
**의존성**: `oncrix-lib`

### 디스패처 (`dispatch.rs`)

```rust
#[repr(C)]
pub struct SyscallArgs {
    pub number: u64,  // RAX
    pub arg0: u64,    // RDI
    pub arg1: u64,    // RSI
    pub arg2: u64,    // RDX
    pub arg3: u64,    // R10
    pub arg4: u64,    // R8
    pub arg5: u64,    // R9
}

pub fn dispatch(args: &SyscallArgs) -> i64;
```

시스콜 번호 테이블: [ARCHITECTURE.ko.md — 시스콜 테이블](ARCHITECTURE.ko.md#시스콜-테이블).
ONCRIX IPC 확장: 512-516. 알 수 없는 번호 → `-38` (ENOSYS).

### 핸들러 (`handler.rs`)

22개 핸들러 스텁. `error_to_errno(Error) → i64`.
`StatBuf` repr(C): `st_ino`, `st_mode`, `st_nlink`, `st_uid`, `st_gid`, `st_size`.

---

## oncrix-kernel

**경로**: `crates/kernel/src/`
**역할**: 마이크로커널 통합 — 모든 컴포넌트를 연결.
**의존성**: 나머지 모든 크레이트.

### 진입점 (`main.rs`)

```rust
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    kernel_main();
}
```

`#[panic_handler]`: 시리얼 출력 후 정지.

### ELF 로더 (`elf.rs`)

```rust
pub struct Elf64Header { /* e_ident, e_type, e_machine, e_entry, e_phoff, e_phnum... */ }
pub struct Elf64Phdr   { /* p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz... */ }
```

`parse_header()` → `ElfInfo`, `load_segments()` → `LoadedSegment` 배열.

### Exec (`exec.rs`)

| 상수 | 값 |
|------|-----|
| USER_STACK_SIZE | 64 KiB |
| MAX_ELF_SIZE | 16 MiB |
| 스택 위치 | `USER_SPACE_END - 0xFFF` |

`prepare_exec(elf_data)`: ELF 파싱 → AddressSpace 생성 → PT_LOAD → VmRegion →
스택 → brk 계산 → `ExecInfo` 반환.

### 유저 접근 (`uaccess.rs`)

`validate_user_range()`, `copy_from_user()`, `copy_to_user()`,
`validate_user_string()`, `get_user_u64()`, `put_user_u64()`.

### 선점 스케줄러 (`sched.rs`)

`DEFAULT_SLICE=10`, `MIN=1`, `MAX=50` 틱.
`timer_tick()`, `reset_slice(priority)`, `disable()`/`enable()`.

### x86_64 아키텍처 (`arch/x86_64/`)

| 파일 | 내용 |
|------|------|
| `init.rs` | GDT/IDT/힙/스케줄러/PIC+PIT 초기화 |
| `exceptions.rs` | 5 예외 핸들러 (#DE, #UD, #DF, #GP, #PF) |
| `interrupts.rs` | 타이머 (IRQ 0), 키보드 (IRQ 1), 스퓨리어스 (IRQ 7) |
| `context.rs` | `CpuContext`, `switch_context` 어셈블리 |
| `syscall_entry.rs` | SYSCALL/SYSRET MSR 설정, 진입/종료 어셈블리 |
| `usermode.rs` | `iretq`를 통한 `jump_to_usermode` |
| `kthread.rs` | 스레드 풀 (32 스레드, 8 KiB 스택) |
| `multiboot2.rs` | `.multiboot2` 섹션의 Multiboot2 헤더 |

---

## 에러 처리 패턴

```rust
use oncrix_lib::{Error, Result};

pub fn allocate_page() -> Result<PhysAddr> {
    let frame = frame_allocator
        .allocate()
        .ok_or(Error::OutOfMemory)?;
    Ok(frame.start_address())
}
```

**규칙**: `unwrap()`/`expect()` 금지, `?`로 전파,
`Option` → `Result`는 `ok_or(Error::...)`,
시스콜 계층에서 `error_to_errno()`로 변환.

---

## 테스트 전략

| 수준 | 방법 | 위치 |
|------|------|------|
| 단위 | `#[cfg(test)]` 모듈 | 파일별 `mod tests` |
| 통합 | 크레이트 간 테스트 | `tests/` 디렉토리 |
| 아키텍처 | 조건부 컴파일 | `#[cfg(target_arch = "...")]` |
| 시스템 | QEMU 전체 부트 | `scripts/run-qemu.sh` |

---

## 빌드 & CI

### 요구사항

- Rust 1.85+ (`#![no_std]` 기능을 위해 nightly)
- QEMU 7.0+ (시스템 테스트)
- `rust-src` 컴포넌트 (`rustup component add rust-src`)

### 검증 명령

```bash
cargo fmt --all -- --check && cargo clippy --workspace -- -D warnings && cargo build --workspace
```

---

## 용어집

| 용어 | 정의 |
|------|------|
| **APIC** | Advanced Programmable Interrupt Controller — x86 인터럽트 하드웨어 |
| **Capability** | 리소스에 대한 특정 접근 권한을 부여하는 위조 불가능한 토큰 |
| **CoW** | Copy-on-Write — fork 후 지연 페이지 복제 |
| **DMA** | Direct Memory Access — 하드웨어 주도 메모리 전송 |
| **ELF** | Executable and Linkable Format — 표준 실행 파일 형식 |
| **GDT** | Global Descriptor Table — x86 세그먼트 디스크립터 테이블 |
| **HAL** | Hardware Abstraction Layer — 플랫폼 독립 하드웨어 인터페이스 |
| **IDT** | Interrupt Descriptor Table — x86 인터럽트 핸들러 등록 |
| **IPC** | Inter-Process Communication — 프로세스 간 메시지 패싱 |
| **IST** | Interrupt Stack Table — 벡터별 스택 전환 (x86_64) |
| **MADT** | Multiple APIC Description Table — 인터럽트 컨트롤러용 ACPI 테이블 |
| **MMU** | Memory Management Unit — 가상-물리 주소 변환 하드웨어 |
| **PIT** | Programmable Interval Timer — 레거시 8254 타이머 칩 |
| **POSIX** | Portable Operating System Interface — 유닉스 API 표준 |
| **RSDP** | Root System Description Pointer — ACPI 진입점 구조체 |
| **TCB** | Trusted Computing Base — 보안을 위해 올바른 최소 코드 |
| **TLB** | Translation Lookaside Buffer — 페이지 테이블 엔트리 MMU 캐시 |
| **TSS** | Task State Segment — x86 특권 수준 스택 저장 |
| **VFS** | Virtual File System — 통합 파일 시스템 추상화 |
| **XSDT** | Extended System Description Table — ACPI 테이블 인덱스 (64비트) |
