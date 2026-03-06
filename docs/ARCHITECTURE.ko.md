# ONCRIX 아키텍처

[English](ARCHITECTURE.md)

ONCRIX 운영체제의 아키텍처 기술 레퍼런스 문서입니다.
설계 철학, 커널 구조, 하드웨어 인터페이스, 타 OS 비교, 각 서브시스템의
기술 사양을 다룹니다.

---

## 목차

1. [설계 철학](#설계-철학)
2. [커널 아키텍처 비교](#커널-아키텍처-비교)
3. [계층 아키텍처](#계층-아키텍처)
4. [부트 시퀀스](#부트-시퀀스)
5. [메모리 모델](#메모리-모델)
6. [프로세스 & 스레드 모델](#프로세스--스레드-모델)
7. [스케줄링](#스케줄링)
8. [프로세스 간 통신](#프로세스-간-통신)
9. [가상 파일 시스템](#가상-파일-시스템)
10. [시스콜 인터페이스](#시스콜-인터페이스)
11. [인터럽트 & 예외 처리](#인터럽트--예외-처리)
12. [보안 아키텍처](#보안-아키텍처)
13. [POSIX 호환 전략](#posix-호환-전략)
14. [타겟 플랫폼](#타겟-플랫폼)
15. [크레이트 의존성 그래프](#크레이트-의존성-그래프)

---

## 설계 철학

ONCRIX는 하나의 원칙을 따릅니다: **하드웨어 특권으로 실행되는 코드를 최소화한다**.
유저 스페이스에서 실행할 수 있는 것은 전부 유저 스페이스에서 실행합니다.
커널은 하드웨어 자원에 대한 접근을 중재하고, 격리된 서비스 간 메시지를
전달하기 위해서만 존재합니다.

### 5대 원칙

| # | 원칙 | 설명 |
|---|------|------|
| 1 | **최소 커널** | 스케줄링, IPC, 페이지 테이블 관리만 Ring 0에서 실행. TCB를 작고 감사 가능하게 유지. |
| 2 | **메시지 패싱 IPC** | 모든 OS 서비스 간 통신은 타입화된, Capability 보호 IPC 채널을 통해 수행. 우회 경로 없음. |
| 3 | **Capability 기반 보안** | 접근 권한은 IPC 엔드포인트에 부여된 위조 불가능한 토큰. 암묵적 권한 없음. |
| 4 | **장애 격리** | 드라이버, 파일 시스템, 네트워크 스택이 일반 유저 스페이스 프로세스로 실행. 크래시 시 해당 프로세스만 재시작. |
| 5 | **엣지에서의 POSIX** | POSIX 호환성은 유저 스페이스 라이브러리/서비스에서 구현. 커널은 메시지 패싱 API만 노출. |

### 시스템 언어로서의 Rust

ONCRIX는 전체가 Rust로 작성됩니다 (`#![no_std]`, C 코드 제로).
스타일 선택이 아닌 근본적인 안전성 결정:

| 속성 | Rust 보장 방식 |
|------|---------------|
| 널 역참조 없음 | 널 포인터 대신 `Option<T>` |
| 버퍼 오버플로 없음 | 경계 검사 슬라이스와 배열 |
| Use-after-free 없음 | 소유권 모델 — 단일 소유자, 이동 시맨틱 |
| 데이터 레이스 없음 | 빌림 검사기가 `&mut T` 별칭 방지 |
| 미초기화 메모리 없음 | 사용 전 초기화 필수 |

`unsafe` 블록은 하드웨어 상호작용(MMIO, 인라인 어셈블리, 페이지 테이블)에만 허용.
모든 `unsafe` 블록에 `// SAFETY:` 주석 필수.

---

## 커널 아키텍처 비교

### 모놀리식 vs. 마이크로커널

```
모놀리식 (Linux, FreeBSD)                마이크로커널 (QNX, ONCRIX)
┌─────────────────────────────┐          ┌─────────────────────────────┐
│       커널 (Ring 0)          │          │   유저 스페이스 (Ring 3)      │
│                             │          │  FS서버    │ 네트워크서버    │
│ 스케줄러                     │          │  드라이버  │ 셸             │
│ 메모리 관리자                 │          │  → 크래시 = 해당 프로세스만  │
│ 파일 시스템 (ext4, xfs..)    │          ├─────────────────────────────┤
│ 네트워크 스택 (TCP/IP)       │          │       커널 (Ring 0)          │
│ 모든 디바이스 드라이버        │          │  스케줄러 + IPC + 페이지     │
│ 보안 모듈                    │          │  → 최소 공격 표면            │
│                             │          │                             │
│ → 어디든 버그 = 커널 패닉    │          │  → ~10K LoC만 위험          │
│ → ~3000만 줄이 위험          │          │    (Linux의 ~3000만 대비)   │
└─────────────────────────────┘          └─────────────────────────────┘
```

### OS 비교표

| | Linux | FreeBSD | QNX | ONCRIX |
|--|-------|---------|-----|--------|
| **커널 유형** | 모놀리식 | 모놀리식 (모듈식) | 마이크로커널 | 마이크로커널 |
| **Ring 0 코드** | ~3000만 줄 | ~수백만 줄 | < 10만 줄 | 최소화 (목표) |
| **언어** | C (+ 일부 Rust) | C | C | **Rust** (C 제로) |
| **드라이버 위치** | 커널 내부 | 커널 (일부 KLD) | 유저 스페이스 | 유저 스페이스 |
| **파일 시스템** | 커널 내부 | 커널 내부 | 유저 스페이스 서버 | 유저 스페이스 서버 |
| **IPC 모델** | 파이프, 소켓, 시그널, futex | 파이프, 소켓, 시그널 | 동기 메시지 패싱 | 동기 메시지 패싱 |
| **장애 격리** | 없음 — 드라이버 버그 = 커널 패닉 | 없음 | 완전 — 서비스 재시작 | 완전 — 서비스 재시작 |
| **보안 모델** | DAC + SELinux/AppArmor | DAC + MAC (Capsicum) | Capability 기반 | Capability 기반 |
| **POSIX** | 거의 완전 (미인증) | 완전 (POSIX.1 인증) | 완전 (POSIX.1 인증) | 목표: POSIX.1-2024 (Linux x86_64 ABI) |
| **실시간성** | PREEMPT_RT 패치 필요 | 제한적 소프트 RT | 하드 실시간 (인증) | 선점형 (RT 아직) |
| **메모리 안전** | 수동 (C) | 수동 (C) | 수동 (C) | 컴파일러 강제 (Rust) |
| **라이선스** | GPL-2.0 | BSD-2-Clause | 상용 (비공개) | **Apache-2.0** |

### 각 OS에서 가져온 것

| 출처 | 채택 | 차별화 |
|------|------|--------|
| **QNX** | 마이크로커널, 메시지 패싱 IPC, Capability 보안, 장애 격리, 서비스 재시작 | 오픈소스 (Apache-2.0), C 대신 Rust |
| **Linux** | POSIX 시스콜 ABI (x86_64 번호), 실용적 호환성, 생태계 교훈 | 모놀리식 대신 마이크로커널, Ring 0에 드라이버 없음 |
| **FreeBSD** | BSD 스타일 코드 구성, Capsicum 영감 | 모놀리식 아님, C 대신 Rust |
| **seL4** | 형식 검증 마인드셋, 최소 TCB (~10K LoC), Capability 설계 패턴 | 실용적 POSIX 호환, Isabelle/HOL 증명 대신 Rust 안전성 |
| **MINIX 3** | 자가 복구 마이크로커널, 자동 드라이버 재시작, 교육 중심 설계 | Rust, 현대 IPC, 프로덕션급 성능 목표 |

### 한 줄 요약

> **QNX의 구조적 장점 + Rust 메모리 안전성 + Linux ABI 호환 + 오픈소스 (Apache-2.0)**

---

## 계층 아키텍처

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

### 계층별 역할

| 계층 | Ring | 크레이트 | 역할 |
|------|------|----------|------|
| **Bootloader** | — | `oncrix-bootloader` | Multiboot2 핸드오프, 메모리 맵, 커널 로드 |
| **Microkernel** | 0 | `oncrix-kernel` | 스케줄러, 코어 IPC 디스패치, 페이지 테이블 조작, 예외/IRQ 라우팅 |
| **HAL** | 0 | `oncrix-hal` | GDT/IDT, PIC/APIC, PIT, UART, ACPI — 모두 트레이트 뒤에 격리 |
| **Memory** | 0 | `oncrix-mm` | 물리 프레임 할당기, 페이지 테이블, 커널 힙, 주소 공간 |
| **Process** | 0/3 | `oncrix-process` | Process/Thread 구조체, PID/TID, 스케줄러, fork, 시그널 |
| **IPC** | 0→3 | `oncrix-ipc` | 채널(링 버퍼), 엔드포인트 레지스트리, 메시지 형식 |
| **Syscall** | 3→0 | `oncrix-syscall` | POSIX ABI 디스패처, 핸들러 스텁, errno 매핑 |
| **VFS** | 3 | `oncrix-vfs` | Inode/dentry/superblock, ramfs/devfs/procfs, 파이프, 경로 해석 |
| **Drivers** | 3 | `oncrix-drivers` | Driver 트레이트, 디바이스 레지스트리, char/block 추상화 |
| **Lib** | — | `oncrix-lib` | Error 열거형, Result<T>, 공유 타입 |

---

## 부트 시퀀스

커널은 엄격한 7단계 초기화 시퀀스를 거칩니다. 각 단계는 이전 단계의
성공적 완료에 의존합니다.

```
Phase 1: 시리얼 콘솔
  │  UART 16550, COM1 (0x3F8), 115200 baud, 8N1
  │  이후 모든 출력이 여기로
  v
Phase 2: GDT + TSS
  │  5 세그먼트: null, kernel code (0x08), kernel data (0x10),
  │              user data (0x1B), user code (0x23)
  │  TSS: 셀렉터 0x28 (더블 폴트 스택: 16 KiB)
  v
Phase 3: IDT
  │  256 인터럽트 벡터
  │  예외 핸들러: #DE (0), #UD (6), #DF (8, IST1), #GP (13), #PF (14)
  v
Phase 4: 커널 힙
  │  LinkedListAllocator, 256 KiB
  │  First-fit 할당 + 병합
  v
Phase 5: 스케줄러
  │  라운드 로빈, 256 스레드 슬롯
  │  idle + init 커널 스레드 생성
  v
Phase 6: SYSCALL/SYSRET
  │  MSR 설정:
  │    EFER (0xC000_0080) — SCE 비트 설정
  │    STAR (0xC000_0081) — kernel CS=0x08, user base=0x10
  │    LSTAR (0xC000_0082) — 진입점 주소
  │    FMASK (0xC000_0084) — 진입 시 IF 마스크
  v
Phase 7: PIC + PIT
  │  8259 PIC: ICW1-4, IRQ 0-15 → 벡터 32-47 리맵
  │  PIT: 채널 0, rate generator 모드, ~100 Hz (디바이저 11932)
  │  [선택: PIT 채널 2를 사용한 APIC 타이머 캘리브레이션]
  v
  커널 준비 완료 — halt loop 또는 첫 태스크 스케줄
```

### 메모리 레이아웃 (Higher-Half)

```
가상 주소 공간 (x86_64, 48비트 정규화)
┌──────────────────────────────────────────┐ 0xFFFF_FFFF_FFFF_FFFF
│                                          │
│  커널 공간                                │
│  Base: 0xFFFF_FFFF_8000_0000             │
│  (higher-half, 링커 스크립트)              │
│                                          │
├──────────────────────────────────────────┤ 0xFFFF_8000_0000_0000
│                                          │  KERNEL_SPACE_START
│  (비정규 주소 구멍)                        │
│                                          │
├──────────────────────────────────────────┤ 0x0000_7FFF_FFFF_FFFF
│                                          │  USER_SPACE_END
│  유저 공간                                │
│  스택 상단: USER_SPACE_END - 0xFFF        │
│  힙 (brk): 마지막 PT_LOAD 위              │
│  코드/데이터: ELF PT_LOAD에서 로드         │
│  Base: 0x0000_0000_0040_0000             │
│                                          │  USER_SPACE_START
├──────────────────────────────────────────┤ 0x0000_0000_0000_0000
```

---

## 메모리 모델

### 물리 메모리

| 항목 | 구현 | 상세 |
|------|------|------|
| **할당기** | 비트맵 (`BitmapAllocator`) | 32,768 프레임 × 4 KiB = **128 MiB** 물리 RAM |
| **저장소** | `[u64; 512]` | 512 워드 × 64 비트 = 32,768 프레임 비트 |
| **비트 규약** | 0 = 빈 공간, 1 = 사용 중 | `mark_range_free()`, `mark_range_used()` |
| **할당** | First-fit 스캔 | 비트맵 워드에서 0 비트 탐색 |
| **프레임 크기** | 4,096 바이트 | `PAGE_SIZE = 4096`, `PAGE_SHIFT = 12` |

### 가상 메모리

**4단계 페이지 테이블 (x86_64)**:

```
가상 주소 (48비트 정규화):
┌────────┬────────┬────────┬────────┬──────────────┐
│ PML4   │ PDPT   │  PD    │  PT    │   Offset     │
│ [47:39]│ [38:30]│ [29:21]│ [20:12]│   [11:0]     │
│ 9 비트  │ 9 비트  │ 9 비트  │ 9 비트  │  12 비트     │
└────────┴────────┴────────┴────────┴──────────────┘
   512      512      512      512     4096 바이트
  엔트리   엔트리   엔트리   엔트리    페이지당
```

**페이지 테이블 엔트리 플래그**:

| 비트 | 이름 | 설명 |
|------|------|------|
| 0 | `PRESENT` | 페이지 매핑됨 |
| 1 | `WRITABLE` | 쓰기 가능 |
| 2 | `USER` | 유저 모드 접근 가능 |
| 3 | `WRITE_THROUGH` | Write-through 캐싱 |
| 4 | `NO_CACHE` | 캐싱 비활성화 |
| 5 | `ACCESSED` | CPU가 접근 시 설정 |
| 6 | `DIRTY` | CPU가 쓰기 시 설정 |
| 7 | `HUGE_PAGE` | 2 MiB 페이지 (PD) 또는 1 GiB (PDPT) |
| 8 | `GLOBAL` | CR3 전환 시 플러시 안 함 |
| 63 | `NO_EXECUTE` | NX — 명령어 페치 비활성화 |

**TLB 관리**: `flush_tlb_page(addr)`는 `invlpg` 사용, `flush_tlb_all()`은 `CR3` 리로드.

### 커널 힙

| 속성 | 값 |
|------|-----|
| 할당기 | `LinkedListAllocator` |
| 크기 | 256 KiB |
| 알고리즘 | First-fit + 프리 블록 분할/병합 |
| 블록 헤더 | `FreeBlock { size: usize, next: *mut FreeBlock }` |
| 정렬 | 요청된 정렬에 맞춰 패딩 |
| 스레드 안전 | `UnsafeCell` 래퍼 (싱글 코어 가정) |

### 프로세스별 주소 공간

| 속성 | 값 |
|------|-----|
| 구조체 | `AddressSpace` |
| PML4 저장 | 루트 페이지 테이블의 물리 주소 |
| 최대 영역 | 64 `VmRegion` 슬롯 |
| 중복 검사 | `add_region()` 시 선형 스캔 |
| USER_SPACE_START | `0x0000_0000_0040_0000` |
| USER_SPACE_END | `0x0000_7FFF_FFFF_FFFF` |
| KERNEL_SPACE_START | `0xFFFF_8000_0000_0000` |

**VmRegion**:

```rust
pub struct VmRegion {
    pub start: VirtAddr,  // 페이지 정렬 시작
    pub size: usize,      // 영역 크기 (바이트)
    pub prot: Protection, // READ | WRITE | EXEC
    pub kind: RegionKind, // Code, Data, Heap, Stack, Mmap
}
```

**보호 플래그**: `READ = 0b001`, `WRITE = 0b010`, `EXEC = 0b100`.
조합: `RW = 0b011`, `RX = 0b101`, `RWX = 0b111`.

---

## 프로세스 & 스레드 모델

### Process

```rust
pub struct Process {
    pid: Pid,                              // u64 뉴타입
    state: ProcessState,                   // Active | Exited
    threads: [Option<Tid>; 64],            // 최대 64 스레드
    thread_count: usize,
}
```

**PID 할당**: 전역 `NEXT_PID` 카운터에 `fetch_add` (Relaxed 순서).
`Pid(0)`은 `KERNEL`으로 예약.

### Thread

```rust
pub struct Thread {
    tid: Tid,                // u64 뉴타입
    pid: Pid,                // 소속 프로세스
    state: ThreadState,      // Ready | Running | Blocked | Exited
    priority: Priority,      // 0 (최고) — 255 (유휴)
    stack_pointer: u64,      // 컨텍스트 스위칭용 저장 RSP
}
```

**우선순위**: `HIGHEST = 0`, `NORMAL = 128`, `IDLE = 255`.

### 컨텍스트 스위칭 (x86_64)

callee-saved 레지스터 6개 + RSP + RIP를 저장/복원:

```rust
pub struct CpuContext {
    pub rbx: u64,  pub rbp: u64,
    pub r12: u64,  pub r13: u64,
    pub r14: u64,  pub r15: u64,
    pub rsp: u64,  pub rip: u64,
}
```

`switch_context(old, new)` 어셈블리 동작:
1. `rbx, rbp, r12-r15`를 현재 스택에 push
2. RSP를 `old.rsp`에 저장
3. `new.rsp`에서 RSP 로드
4. 새 스택에서 `r15-r12, rbp, rbx` pop
5. return (RIP는 새 스택에 있음)

### Fork

`fork_process(parent, priority)` → `(ForkResult, Process, Thread)`:
1. 새 PID/TID를 원자적으로 할당
2. 새 PID로 자식 `Process` 생성
3. 자식의 스레드 목록에 자식 TID 추가
4. 부모 우선순위를 상속하는 자식 `Thread` 생성
5. 자식 객체 반환 — *호출자*가 담당:
   - CoW 매핑으로 페이지 테이블 복제
   - 부모의 CPU 컨텍스트 복사
   - 자식 컨텍스트에서 RAX = 0 설정
   - 자식 스레드를 스케줄러에 추가

**Copy-on-Write 트래커**:

```rust
pub struct CowTracker {
    states: [CowState; 4096],  // 프레임별 상태
    count: usize,              // 공유 프레임 수
}

pub enum CowState {
    Shared(u16),   // 참조 카운트 (≥ 2)
    Exclusive,     // 단일 소유, 쓰기 가능
}
```

- `share(frame_idx)`: `Exclusive → Shared(2)`, `Shared(n) → Shared(n+1)`
- `unshare(frame_idx)`: `Shared(n>2) → Shared(n-1)`, `Shared(2) → Exclusive`

### 시그널

| 속성 | 값 |
|------|-----|
| 최대 시그널 | 32 (POSIX 표준 집합) |
| 저장소 | `u32` 비트셋 (마스크 + 대기) |
| 시그널별 액션 | `Default`, `Ignore`, `Handler(u64)` |

**정의된 시그널**: SIGHUP(1), SIGINT(2), SIGQUIT(3), SIGILL(4), SIGABRT(6),
SIGBUS(7), SIGFPE(8), SIGKILL(9), SIGSEGV(11), SIGPIPE(13), SIGALRM(14),
SIGTERM(15), SIGCHLD(17), SIGCONT(18), SIGSTOP(19), SIGTSTP(20).

---

## 스케줄링

### 라운드 로빈 스케줄러

| 속성 | 값 |
|------|-----|
| 최대 스레드 | 256 |
| 알고리즘 | 커서 기반 라운드 로빈 + 우선순위 타임 슬라이스 |
| 연산 | `add()`, `remove()`, `schedule()`, `block_current()`, `unblock()` |

### 선점형 스케줄링

타이머 구동 스케줄러. PIT 틱마다 (~100 Hz = 10 ms 간격):

1. `timer_tick()`이 `remaining_ticks` 감소
2. `remaining_ticks`가 0이 되면 → 강제 컨텍스트 스위칭
3. 새 스레드는 우선순위에 따른 타임 슬라이스 획득

**우선순위 → 타임 슬라이스 매핑**:

```
Priority 0   (최고)  → 50 틱 (500 ms)
Priority 128 (보통)  → 25 틱 (250 ms)
Priority 255 (유휴)  →  1 틱 (10 ms)

공식: slice = MAX_SLICE - (priority * (MAX_SLICE - MIN_SLICE) / 255)
      MAX_SLICE = 50, MIN_SLICE = 1
```

**선점 제어** (중첩 가능):

```rust
pub struct PreemptionState {
    remaining_ticks: u32,    // 현재 슬라이스 남은 틱
    total_ticks: u64,        // 부트 이후 총 틱
    preempt_enabled: bool,   // 마스터 활성화 플래그
    preempt_count: u32,      // 중첩 깊이
    forced_switches: u64,    // 통계: 선점 이벤트
    voluntary_yields: u64,   // 통계: yield() 호출
}
```

- `disable()`: `preempt_count` 증가, `preempt_enabled = false`
- `enable()`: `preempt_count` 감소, 카운트 0이면 재활성화
- 비활성 중 슬라이스 만료 시 `true` 반환 (지연된 스위칭 필요)

### 커널 스레드 풀

| 속성 | 값 |
|------|-----|
| 최대 스레드 | 32 |
| 스택 크기 | 8 KiB/스레드 |
| 초기 스레드 | `idle_thread_entry()`, `init_thread_entry()` |
| 스택 저장 | 정적 배열 (`KTHREAD_STACKS`) |

---

## 프로세스 간 통신

IPC는 마이크로커널의 핵심. 모든 서비스 통신이 타입화된 메시지 채널을 통해 수행.

### 메시지 형식

```rust
pub struct Message {
    header: MessageHeader,
    payload: [u8; 256],        // MAX_INLINE_PAYLOAD = 256
}

pub struct MessageHeader {
    pub sender: EndpointId,    // u64
    pub receiver: EndpointId,  // u64
    pub tag: u32,              // 메시지 타입 식별자
    pub payload_len: u32,      // 실제 페이로드 바이트 (0..256)
}
```

### 채널

각 채널은 두 엔드포인트를 연결하는 **단방향 링 버퍼**:

```rust
pub struct Channel {
    src: EndpointId,
    dst: EndpointId,
    buffer: [MessageSlot; 16],  // CHANNEL_CAPACITY = 16
    head: usize,                // 다음 읽기 위치
    tail: usize,                // 다음 쓰기 위치
    count: usize,               // 버퍼 내 메시지 수
}
```

**MessageSlot**: `occupied: bool`, `sender: EndpointId`, `tag: u32`,
`payload_len: u32`, `payload: [u8; 256]`.

### 채널 레지스트리

- 용량: **64 채널**
- 조회: 엔드포인트 쌍 `(src, dst)`으로
- 연산: `create(src, dst)`, `find(src, dst)`, `remove(id)`

### SyncIpc 트레이트

```rust
pub trait SyncIpc {
    fn send(&mut self, msg: &Message) -> Result<()>;
    fn receive(&mut self) -> Result<Message>;
    fn reply(&mut self, msg: &Message) -> Result<()>;
    fn call(&mut self, request: &Message) -> Result<Message>;  // send + receive
}
```

---

## 가상 파일 시스템

### 구조

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
         InodeOps 트레이트 — 파일시스템별 구현
```

### 핵심 타입

**Inode**:
```rust
pub struct Inode {
    pub ino: InodeNumber,     // u64 뉴타입
    pub file_type: FileType,  // Regular | Directory | Symlink | CharDevice |
                              // BlockDevice | Fifo | Socket
    pub mode: FileMode,       // u16 — POSIX 권한 비트
    pub size: u64,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
}
```

**InodeOps 트레이트** — 모든 파일시스템이 구현해야 함:

| 메서드 | 시그니처 | 설명 |
|--------|----------|------|
| `lookup` | `(&self, dir, name) → Result<InodeNumber>` | 이름으로 자식 찾기 |
| `create` | `(&mut self, dir, name, mode) → Result<InodeNumber>` | 일반 파일 생성 |
| `mkdir` | `(&mut self, dir, name, mode) → Result<InodeNumber>` | 디렉토리 생성 |
| `unlink` | `(&mut self, dir, name) → Result<()>` | 파일 삭제 |
| `rmdir` | `(&mut self, dir, name) → Result<()>` | 디렉토리 삭제 |
| `read` | `(&self, ino, offset, buf) → Result<usize>` | 데이터 읽기 |
| `write` | `(&mut self, ino, offset, data) → Result<usize>` | 데이터 쓰기 |
| `truncate` | `(&mut self, ino, size) → Result<()>` | 파일 크기 설정 |

### 파일 디스크립터 테이블

| 속성 | 값 |
|------|-----|
| 최대 열린 파일 | 256 (`MAX_OPEN_FILES`) |
| 예약 FD | `STDIN = 0`, `STDOUT = 1`, `STDERR = 2` |
| 연산 | `alloc()`, `get()`, `get_mut()`, `close()`, `dup2()` |

**OpenFlags**: `O_RDONLY = 0`, `O_WRONLY = 1`, `O_RDWR = 2`,
`O_CREAT = 0o100`, `O_TRUNC = 0o1000`, `O_APPEND = 0o2000`.

### 파일시스템

**ramfs** — 인메모리 파일시스템:

| 속성 | 값 |
|------|-----|
| 최대 inode | 128 |
| 최대 파일 크기 | 4,096 바이트 (1 페이지) |
| 디렉토리당 최대 엔트리 | 32 |
| 이름 길이 | 255 바이트 |
| 데이터 저장 | 파일당 인라인 `[u8; 4096]` |

**devfs** — 디바이스 파일시스템:

| 속성 | 값 |
|------|-----|
| 최대 디바이스 노드 | 64 |
| 디바이스 타입 | Char, Block |
| 연산 | 등록, 해제, 이름으로 조회 |

**procfs** — 프로세스 정보 파일시스템:

| 가상 파일 | 내용 |
|-----------|------|
| `/proc/version` | OS 버전 문자열 |
| `/proc/uptime` | 시스템 가동 시간 |
| `/proc/meminfo` | 메모리 사용 통계 |
| `/proc/cpuinfo` | CPU 정보 |

### 파이프

| 속성 | 값 |
|------|-----|
| 버퍼 크기 | 4,096 바이트 (링 버퍼) |
| 최대 파이프 수 | 64 (`PipeRegistry`) |
| 시맨틱 | POSIX — write 닫히면 EOF, read 닫히면 EPIPE |

**상태 머신**:
- `read()` 빈 파이프 + write 열림 → `WouldBlock`
- `read()` 빈 파이프 + write 닫힘 → `Ok(0)` (EOF)
- `write()` 파이프 + read 닫힘 → `IoError` (EPIPE)
- `write()` 꽉 찬 파이프 → `WouldBlock`

### 경로 해석

`resolve_path(path, root_inode, fs, mount_table, dcache)`:
1. 경로를 `/`로 분할하여 최대 64 컴포넌트
2. `root_inode`에서 시작
3. 각 컴포넌트에 대해:
   - `.` 건너뛰기 (현재 디렉토리)
   - `fs.lookup(current_dir, component)` → 자식 inode
   - 자식이 디렉토리인지 확인 (마지막 컴포넌트 제외)
   - 자식으로 이동
4. 최종 inode 번호 반환

### VFS 연산

| 연산 | 동작 |
|------|------|
| `vfs_read(fd_table, fd, buf, fs, lookup)` | fd의 오프셋에서 읽기, 오프셋 전진 |
| `vfs_write(fd_table, fd, data, fs, lookup)` | 오프셋에 쓰기 (O_APPEND면 끝에), 오프셋 전진 |
| `vfs_lseek(fd_table, fd, offset, whence, lookup)` | SEEK_SET(0), SEEK_CUR(1), SEEK_END(2) + 오버플로 검사 |
| `vfs_stat(inode)` → `StatInfo` | FileType + FileMode → POSIX `st_mode` 인코딩 |

**st_mode 인코딩**: Regular=`0o100000`, Directory=`0o040000`,
Symlink=`0o120000`, CharDevice=`0o020000`, BlockDevice=`0o060000`,
Fifo=`0o010000`, Socket=`0o140000`. 권한 비트와 결합 (`mode & 0o7777`).

---

## 시스콜 인터페이스

### ABI

**Linux x86_64 시스콜 ABI**를 바이너리 호환을 위해 사용:

| 레지스터 | 용도 |
|----------|------|
| `RAX` | 시스콜 번호 |
| `RDI` | 인자 0 |
| `RSI` | 인자 1 |
| `RDX` | 인자 2 |
| `R10` | 인자 3 |
| `R8` | 인자 4 |
| `R9` | 인자 5 |
| `RAX` (반환) | 결과 (음수 = -errno) |

`SYSCALL` 명령어 → 커널 `LSTAR` 핸들러 → `dispatch()`.

### 시스콜 테이블

| 번호 | 이름 | 분류 |
|------|------|------|
| 0 | `read` | I/O |
| 1 | `write` | I/O |
| 2 | `open` | 파일 |
| 3 | `close` | 파일 |
| 4 | `stat` | 파일 |
| 5 | `fstat` | 파일 |
| 8 | `lseek` | 파일 |
| 9 | `mmap` | 메모리 |
| 11 | `munmap` | 메모리 |
| 12 | `brk` | 메모리 |
| 13 | `rt_sigaction` | 시그널 |
| 22 | `pipe` | IPC |
| 33 | `dup2` | 파일 |
| 39 | `getpid` | 프로세스 |
| 57 | `fork` | 프로세스 |
| 59 | `execve` | 프로세스 |
| 60 | `exit` | 프로세스 |
| 61 | `wait4` | 프로세스 |
| 62 | `kill` | 시그널 |
| 83 | `mkdir` | 파일 |
| 84 | `rmdir` | 파일 |
| 87 | `unlink` | 파일 |
| 512 | `ipc_send` | ONCRIX IPC |
| 513 | `ipc_receive` | ONCRIX IPC |
| 514 | `ipc_reply` | ONCRIX IPC |
| 515 | `ipc_call` | ONCRIX IPC |
| 516 | `ipc_create_endpoint` | ONCRIX IPC |

알 수 없는 시스콜 번호는 `-38` (`ENOSYS`) 반환.

### 에러 매핑

| `oncrix_lib::Error` | POSIX errno | 값 |
|---------------------|-------------|-----|
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

### 유저 포인터 검증

유저 스페이스 포인터를 역참조하기 전 반드시 검증:

1. 포인터가 `USER_SPACE_START..=USER_SPACE_END` 범위 내
2. `ptr + len`이 오버플로(랩어라운드)하지 않음
3. `ptr + len`이 `USER_SPACE_END + 1`을 초과하지 않음
4. `u64` 연산: 8바이트 정렬 필수

위반 시 `Error::InvalidArgument` 반환.

---

## 인터럽트 & 예외 처리

### IDT 배치

| 벡터 | 소스 | 핸들러 |
|------|------|--------|
| 0 | #DE — 0 나누기 | RIP 출력, 정지 |
| 6 | #UD — 잘못된 명령 | RIP 출력, 정지 |
| 8 | #DF — 더블 폴트 | IST1 (별도 16 KiB 스택), 정지 |
| 13 | #GP — 일반 보호 | 에러 코드 + RIP 출력, 정지 |
| 14 | #PF — 페이지 폴트 | CR2 + 에러 코드 + RIP 출력, 정지 |
| 32 | IRQ 0 — PIT 타이머 | 틱 카운터 증가, 스케줄러 호출 |
| 33 | IRQ 1 — 키보드 | 포트 0x60에서 스캔코드 읽기 |
| 39 | IRQ 7 — 스퓨리어스 | EOI 안 보냄 |

### 8259 PIC 설정

```
마스터 PIC (포트 0x20/0x21)           슬레이브 PIC (포트 0xA0/0xA1)
  IRQ 0 → 벡터 32 (타이머)             IRQ 8  → 벡터 40
  IRQ 1 → 벡터 33 (키보드)             IRQ 9  → 벡터 41
  IRQ 2 → 벡터 34 (캐스케이드)          ...
  ...                                  IRQ 15 → 벡터 47
  IRQ 7 → 벡터 39 (스퓨리어스)

ICW 시퀀스: ICW1=0x11, ICW2=오프셋, ICW3=캐스케이드, ICW4=0x01 (8086 모드)
EOI: 커맨드 포트에 0x20 쓰기 (IRQ ≥ 8이면 마스터 + 슬레이브 둘 다)
```

### Local APIC 타이머

| 레지스터 | 오프셋 | 설명 |
|----------|--------|------|
| ID | 0x020 | APIC ID |
| Version | 0x030 | 버전 및 최대 LVT |
| TPR | 0x080 | 태스크 우선순위 |
| EOI | 0x0B0 | End of Interrupt (0 쓰기) |
| SIVR | 0x0F0 | 스퓨리어스 벡터 (비트 8 = APIC 활성화) |
| LVT Timer | 0x320 | 타이머 벡터 + 모드 |
| Initial Count | 0x380 | 카운트다운 시작 값 |
| Current Count | 0x390 | 현재 카운트다운 (읽기 전용) |
| Divide Config | 0x3E0 | 타이머 주파수 분주기 |

**MMIO 기본 주소**: `0xFEE0_0000`

**캘리브레이션 알고리즘**:
1. APIC 분주를 By16으로, 초기 카운트를 `0xFFFF_FFFF`로 설정
2. PIT 채널 2로 ~10 ms 지연 프로그래밍 (스피커 게이트)
3. PIT 만료 대기
4. APIC 현재 카운트 읽기 → 10 ms 동안의 경과 틱
5. 주파수 계산: `elapsed * 100 * divide_value`

### ACPI 테이블 파싱

**RSDP** (Root System Description Pointer):
- 시그니처: `"RSD PTR "` (8바이트, 후행 공백)
- 탐색: BIOS ROM `0xE0000`–`0xFFFFF`, 16바이트 경계
- 체크섬: 첫 20바이트 합 = 0 (v1), 36바이트 합 = 0 (v2)

**XSDT** (Extended System Description Table):
- 시그니처: `"XSDT"`, 체크섬: 전체 바이트 합 = 0
- 엔트리: 64비트 물리 주소 배열 (최대 32개)

**MADT** (Multiple APIC Description Table):
- 시그니처: `"APIC"`, Local APIC 주소 (32비트) 포함
- 가변 길이 엔트리 (타입 + 길이 헤더):
  - Type 0: Local APIC (APIC ID, 프로세서 ID, 플래그)
  - Type 1: I/O APIC (ID, 주소, GSI 기본)
  - Type 2: Interrupt Source Override (버스, 소스, GSI, 플래그)
- 한계: Local APIC 64개, I/O APIC 8개, Override 16개

---

## 보안 아키텍처

### Capability 모델

```
프로세스 A                          프로세스 B
┌──────────┐                     ┌──────────┐
│ Cap: FS  │──── IPC 채널 ───────│ Cap: Net │
│ Cap: Net │  (capability 검증)   │          │
└──────────┘                     └──────────┘
```

- 각 IPC 엔드포인트는 capability 토큰 보유
- Capability는 위조 불가 — 커널만 발행
- 프로세스는 매칭 capability 없이 서비스 접근 불가
- Capability는 제한된 권한으로 IPC 통해 위임 가능

### 특권 분리

| Ring | 실행 대상 | 신뢰 수준 |
|------|----------|----------|
| Ring 0 | 마이크로커널 (스케줄러, IPC, 페이지 테이블) | 완전 신뢰 |
| Ring 3 | 나머지 전부 (드라이버, FS, 네트워크, 앱) | 비신뢰 |

전통적으로 크래시 빈도가 높은 디바이스 드라이버조차 Ring 3에서 실행.
직접 하드웨어 접근 없이, capability 보호 IPC를 통해 커널에 I/O 요청.

---

## POSIX 호환 전략

### 대상 표준

**POSIX.1-2024 (IEEE Std 1003.1-2024)** — 2024년 6월 발행된 최신 개정판.
[The Open Group](https://pubs.opengroup.org/onlinepubs/9799919799/)에서 무료 열람 가능.

2017 대신 2024를 선택한 이유:
- 레거시 부담 없음 — 처음부터 만드는 OS이므로 deprecated 함수(`tmpnam`, `gets` 등)를 아예 구현 안 함
- C17 정렬이 Rust 타입 모델과 더 잘 맞음 (C99 대비)
- 나노초 타임스탬프 (`_POSIX_TIMESTAMP_RESOLUTION`) 처음부터 의무화
- `getentropy()` 보안 난수 — Capability 보안 모델에 부합

ONCRIX는 POSIX 인증을 추구하지 않음 (The Open Group 상용 라이선스 필요).
**"POSIX.1-2024 compatible"** 이라는 사실적 기술 표현을 사용 (상표 아님).

### POSIX 너머: Linux ABI 호환

POSIX만으로는 실제 앱 실행에 부족. 대부분의 바이너리는 추상적 POSIX가 아닌
Linux용으로 빌드됨. ONCRIX는 3계층으로 실용적 호환성을 목표:

| 계층 | 내용 | 이유 |
|------|------|------|
| **POSIX.1-2024 코어** | 파일 I/O, 프로세스, 시그널, 스레드, 파이프 | 기본 호환 표준 |
| **Linux 확장** | `epoll`, `eventfd`, `timerfd`, `signalfd`, `/proc` 레이아웃 | 실제 앱 대부분이 의존 |
| **libc** | musl 포팅 또는 Rust 네이티브 (relibc 방식) | C/C++ 바이너리 실행에 필수 |

### 구조

커널에서 POSIX를 구현하지 않습니다. 대신:

```
유저 바이너리
  │  syscall 명령어 (RAX = 시스콜 번호)
  v
커널 SYSCALL 핸들러
  │  인자 검증, capability 확인
  v
서비스로 IPC 메시지
  │  시스콜을 타입화된 IPC 메시지로 변환
  v
서비스 프로세스 (유저 스페이스)
  │  VFS 서버, 프로세스 서버, 네트워크 서버 등
  │  실제 작업 수행
  v
IPC 응답
  │  결과가 IPC를 통해 반환
  v
커널 SYSRET
  │  RAX에 결과를 담아 유저 바이너리로 반환
  v
유저 바이너리 계속 실행
```

커널은 POSIX 의미의 "파일"이나 "프로세스"를 이해할 필요 없음 —
주소 공간, 스레드, 메시지만 알면 됨.

### ELF 로더

| 속성 | 값 |
|------|-----|
| 형식 | ELF64 (64비트, 리틀 엔디안) |
| 매직 | `0x7F, 'E', 'L', 'F'` |
| 지원 타입 | `ET_EXEC` (정적), `ET_DYN` (PIE) |
| 아키텍처 | `EM_X86_64` (현재) |
| 최대 세그먼트 | 16 (`PT_LOAD`) |
| 최대 ELF 크기 | 16 MiB |
| 유저 스택 | 64 KiB, `USER_SPACE_END - 0xFFF` |

---

## 타겟 플랫폼

| 아키텍처 | 상태 | 비고 |
|----------|------|------|
| **x86_64** | 주요 | 모든 현재 구현 |
| **aarch64** | 예정 | HAL 모듈 구조 준비 |
| **riscv64** | 예정 | HAL 모듈 구조 준비 |

아키텍처별 코드는 `oncrix-hal`에서 `#[cfg(target_arch = "...")]`로 격리.
새 아키텍처 추가 = HAL 트레이트 구현 (`SerialPort`, `InterruptController`, `Timer`).
상위 크레이트 변경 불필요.

---

## 크레이트 의존성 그래프

```
                    ┌──────────┐
                    │  kernel  │  ← 최상위: 모든 것 통합
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
       │            lib              │  ← 최하위: 공유 타입, 의존성 제로
       └─────────────────────────────┘
```

**의존성 규칙**: 하위 크레이트는 상위 크레이트에 의존하지 않음.
모든 커널 공간 크레이트는 **외부 의존성 제로** (`core`와 `alloc`만).
`oncrix-lib`는 의존성이 전혀 없는 최하위 크레이트.

---

## 기술 스택

| 항목 | 선택 |
|------|------|
| 언어 | Rust 1.85+ (Edition 2024) |
| 빌드 시스템 | Cargo 워크스페이스 |
| 커널 모드 | `#![no_std]` + `#![no_main]` |
| 어셈블리 | `core::arch::asm!` (인라인, 아키텍처 게이트) |
| 부트 프로토콜 | Multiboot2 |
| 테스트 러너 | QEMU (x86_64 시스템 에뮬레이션) |
| CI/CD | GitHub Actions (fmt + clippy + build) |
| 라이선스 | Apache-2.0 |
