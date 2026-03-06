# 변경 이력

[English](../CHANGELOG.md) | **한국어**

이 프로젝트의 모든 주요 변경 사항은 이 파일에 문서화됩니다.

형식은 [Keep a Changelog](https://keepachangelog.com/)를 기반으로 하며,
이 프로젝트는 [Semantic Versioning](https://semver.org/)을 준수합니다.

## [미출시]

### 추가됨

#### 프로젝트 인프라
- 10개 크레이트 Cargo 워크스페이스 (kernel, hal, bootloader, mm, ipc, process, syscall, vfs, drivers, lib)
- GitHub Actions CI/CD 파이프라인 (fmt, clippy, build)
- 개발자 문서, 위키, 검증 체크리스트
- 커뮤니티 파일 (CONTRIBUTING, CODE_OF_CONDUCT, SECURITY)
- 영문 및 한국어 문서
- QEMU 통합 스크립트 및 higher-half 링커 스크립트

#### oncrix-lib
- `Error` 열거형 (10 변형), `Result<T>` 타입 별칭, `Display` 구현

#### oncrix-hal
- `SerialPort`, `InterruptController`, `Timer` 트레이트
- x86_64: UART 16550, GDT (5 세그먼트 + TSS), IDT (256 벡터)
- x86_64: 8259 PIC (IRQ 리맵 32-47), PIT 타이머 (~100 Hz)
- x86_64: Local APIC 타이머 (MMIO, PIT 캘리브레이션, periodic/one-shot)
- x86_64: 공유 포트 I/O (`inb`/`outb`)
- ACPI 파싱 (RSDP v1/v2, XSDT, MADT — Local APIC/IO APIC/Override)

#### oncrix-bootloader
- `BootInfo`, `MemoryMap`, Multiboot2 헤더

#### oncrix-mm
- `PhysAddr`/`VirtAddr` 뉴타입, `Frame`/`Page`, `FrameAllocator` 트레이트
- 비트맵 프레임 할당기 (128 MiB), 4단계 페이지 테이블, TLB 플러시
- 커널 힙 (`LinkedListAllocator`, 256 KiB), `map_page`/`unmap_page`
- 프로세스별 `AddressSpace` (64 VmRegion, 중복 감지)

#### oncrix-ipc
- `Message` (헤더 + 256바이트 페이로드), `EndpointId`, `SyncIpc` 트레이트
- `Channel` 링 버퍼 (16 메시지), `ChannelRegistry` (64 채널)

#### oncrix-process
- `Pid`/`Tid` 뉴타입, `Process` (64 스레드), `Thread`, `Priority`
- 라운드 로빈 스케줄러 (256 스레드), POSIX 시그널 처리 (32 시그널)
- `fork_process()` + `CowTracker` (CoW 참조 카운팅)

#### oncrix-vfs
- Inode, dentry 캐시 (256 엔트리), superblock, 마운트 테이블 (16 마운트)
- `FdTable` (256 fd, dup2), ramfs (128 inode, 4 KiB 파일)
- devfs (64 노드), procfs (version/uptime/meminfo/cpuinfo)
- 파이프 (4 KiB 링 버퍼, 64 파이프, EOF/EPIPE)
- 경로 해석 (`resolve_path`, `vfs_open` + O_CREAT/O_TRUNC)
- VFS 연산 (`vfs_read`, `vfs_write`, `vfs_lseek`, `vfs_stat`)

#### oncrix-syscall
- POSIX 시스콜 번호 (Linux x86_64 ABI), 디스패처, 22개 핸들러
- `StatBuf` repr(C), `error_to_errno()` (10 에러 변형)

#### oncrix-drivers
- `Driver` 트레이트, `DeviceRegistry` (64 디바이스, ID/클래스/IRQ 조회)

#### oncrix-kernel
- 7단계 부트: Serial, GDT, IDT, Heap, Scheduler, SYSCALL, PIC+PIT
- 5 예외 핸들러, 3 IRQ 핸들러 (타이머, 키보드, 스퓨리어스)
- 컨텍스트 스위칭, SYSCALL/SYSRET, Ring 0→3 (`iretq`)
- 커널 스레드 풀 (32 스레드, 8 KiB 스택)
- ELF64 로더, 유저 스페이스 exec, 유저 포인터 검증
- 선점형 스케줄링 (우선순위 기반 타임 슬라이스)
