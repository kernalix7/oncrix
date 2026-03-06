# ONCRIX 개발자 위키

ONCRIX 커널 개발을 위한 종합 가이드입니다.

## 아키텍처 개요

ONCRIX는 **마이크로커널 아키텍처**를 사용하며, 가장 필수적인 서비스만
커널 공간(Ring 0)에서 실행됩니다. 디바이스 드라이버, 파일 시스템,
네트워킹 등 기타 모든 OS 서비스는 IPC를 통해 통신하는 격리된 유저 스페이스
프로세스로 실행됩니다.

### 계층 다이어그램

```
유저 스페이스 (Ring 3)
├── 애플리케이션 (POSIX 호환)
├── 시스템 서비스 (VFS, 네트워킹 등)
├── 디바이스 드라이버 (유저 스페이스)
└── 시스콜 인터페이스
────────────────────────────────
커널 스페이스 (Ring 0)
├── 스케줄러
├── IPC (메시지 패싱)
├── 메모리 관리 (페이지 테이블, 물리 할당기)
└── HAL (인터럽트 라우팅, 타이머, 아키텍처별 코드)
```

### 설계 원칙

1. **최소 커널**: Ring 0에는 스케줄링, IPC, 메모리 관리만 포함
2. **메시지 패싱**: 모든 서비스 간 통신은 타입화된 IPC 메시지를 통해 수행
3. **능력(Capability) 기반 보안**: 접근 권한은 위조 불가능한 토큰
4. **장애 격리**: 크래시된 드라이버가 시스템을 다운시키지 않음
5. **엣지에서의 POSIX**: POSIX 호환성은 유저 스페이스 라이브러리에서 구현

## 크레이트별 가이드

### oncrix-lib
**역할**: 모든 크레이트에서 공유하는 기초 타입.
- `Error` 열거형 — 최상위 에러 타입
- `Result<T>` 타입 별칭
- 공통 상수 및 유틸리티 함수

### oncrix-hal
**역할**: 하드웨어 추상화 계층 — 아키텍처별 코드를 격리.
- CPU 초기화, 특권 수준
- 인터럽트 컨트롤러 (APIC/GIC) 추상화
- 타이머 추상화 (PIT/HPET/APIC timer / ARM 범용 타이머)
- 시리얼 포트 / UART
- 아키텍처 게이트 모듈: `#[cfg(target_arch = "x86_64")]`, `#[cfg(target_arch = "aarch64")]`, `#[cfg(target_arch = "riscv64")]`

### oncrix-bootloader
**역할**: 초기 부팅 및 커널 핸드오프.
- UEFI / Multiboot2 프로토콜 지원
- 메모리 맵 파싱
- 커널 ELF 로딩
- 초기 페이지 테이블 설정
- 초기 디버그 출력을 위한 시리얼 콘솔

### oncrix-mm
**역할**: 메모리 관리 서브시스템.
- 물리 페이지 할당기 (비트맵 / 버디 할당기)
- 가상 메모리 관리자 (페이지 테이블 조작)
- 커널 힙 할당기 (슬랩 / 범프 할당기)
- 프로세스별 주소 공간 관리
- 핵심 타입: `PhysAddr`, `VirtAddr`, `PageTable`, `Frame`, `Page`

### oncrix-ipc
**역할**: 프로세스 간 통신 — 마이크로커널의 핵심.
- 동기 IPC: `send()`, `receive()`, `reply()`
- 비동기 알림
- 공유 메모리 영역
- 능력(Capability) 기반 엔드포인트 관리
- 메시지 형식: 고정 헤더 + 가변 페이로드

### oncrix-process
**역할**: 프로세스 및 스레드 생명주기.
- 프로세스 생성 / 소멸
- 스레드 관리
- 스케줄러 (우선순위 기반 선점형)
- 컨텍스트 스위칭
- 핵심 타입: `Process`, `Thread`, `Pid`, `Tid`, `SchedulerState`

### oncrix-vfs
**역할**: 가상 파일 시스템 추상화.
- 서로 다른 파일 시스템 구현에 대한 통합 파일 연산
- 마운트 테이블 관리
- 경로 해석 (namei)
- 파일 디스크립터 테이블
- POSIX 파일 시맨틱 (open, read, write, close, seek, stat)

### oncrix-drivers
**역할**: 유저 스페이스 디바이스 드라이버 프레임워크.
- 드라이버 등록 및 검색
- 디바이스 트리 / ACPI 추상화
- 공통 드라이버 인터페이스 (블록, 캐릭터, 네트워크)
- DMA 버퍼 관리
- 커널에서 유저 스페이스 드라이버로의 인터럽트 전달

### oncrix-syscall
**역할**: POSIX 호환 시스템 콜 인터페이스.
- 시스콜 ABI 정의 (레지스터 규약)
- 인자 검증 및 정제
- 시스콜 디스패치 테이블
- 유저 스페이스 포인터 검증
- POSIX errno 매핑

### oncrix-kernel
**역할**: 마이크로커널 통합 크레이트 — 모든 것을 연결.
- 커널 진입점 (`_start`)
- 초기화 시퀀스
- 패닉 핸들러
- 전역 상태 관리

## 에러 처리 패턴

모든 실패 가능한 연산은 `oncrix_lib::Result<T>`를 반환합니다:

```rust
use oncrix_lib::{Error, Result};

pub fn allocate_page() -> Result<PhysAddr> {
    let frame = frame_allocator
        .allocate()
        .ok_or(Error::OutOfMemory)?;
    Ok(frame.start_address())
}
```

## 테스트 전략

- **단위 테스트**: 모듈별 `#[cfg(test)]` 블록
- **통합 테스트**: 크레이트 간 `tests/` 디렉토리 테스트
- **아키텍처 테스트**: 조건부 컴파일 `#[cfg(target_arch = "...")]`
- **QEMU 테스트**: QEMU 러너를 사용한 전체 시스템 부팅 테스트

## 빌드 & CI

### 요구사항
- Rust 1.85+ (`#![no_std]` 기능을 위해 nightly 필요)
- QEMU 7.0+ (시스템 테스트용)
- `rust-src` 컴포넌트 (`#![no_std]` 크로스 컴파일용)

### CI 파이프라인
```bash
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo build --workspace
```

## 용어집

| 용어 | 정의 |
|------|------|
| **IPC** | Inter-Process Communication — 프로세스 간 메시지 패싱 |
| **TCB** | Trusted Computing Base — 보안을 위해 반드시 올바른 최소한의 코드 집합 |
| **HAL** | Hardware Abstraction Layer — 플랫폼 독립적 하드웨어 인터페이스 |
| **VFS** | Virtual File System — 통합 파일 시스템 추상화 |
| **MMU** | Memory Management Unit — 가상-물리 주소 변환 하드웨어 |
| **TLB** | Translation Lookaside Buffer — 페이지 테이블 항목용 MMU 캐시 |
| **GDT** | Global Descriptor Table — x86 세그먼트 디스크립터 테이블 |
| **IDT** | Interrupt Descriptor Table — x86 인터럽트 핸들러 등록 |
| **APIC** | Advanced Programmable Interrupt Controller — x86 인터럽트 하드웨어 |
| **UEFI** | Unified Extensible Firmware Interface — 현대 부트 프로토콜 |
| **ELF** | Executable and Linkable Format — 표준 실행 파일 형식 |
| **DMA** | Direct Memory Access — 하드웨어 주도 메모리 전송 |
| **POSIX** | Portable Operating System Interface — 유닉스 API 표준 |
| **Capability** | 리소스에 대한 특정 접근 권한을 부여하는 위조 불가능한 토큰 |
