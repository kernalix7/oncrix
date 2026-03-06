# ONCRIX

**ONCRIX is Not a Copy, Real Independent uniX**

ONCRIX는 **마이크로커널 아키텍처**로 처음부터 새롭게 설계된 운영체제입니다.
완전한 POSIX 호환성을 갖춘 독립적인 유닉스 계열 OS를 목표로 하며,
메모리 안전성, 보안, 성능을 위해 전체를 **Rust**로 작성합니다.

## 왜 ONCRIX인가?

전통적인 모놀리식 커널은 드라이버, 파일 시스템, 네트워킹 등 모든 것을 하나의
특권 주소 공간에 집어넣습니다. 어떤 컴포넌트든 하나의 버그가 전체 시스템을
다운시킬 수 있습니다.

ONCRIX는 다른 접근법을 취합니다:

- **마이크로커널 설계**: 스케줄링, IPC, 기본 메모리 관리만 커널 공간에서 실행
- **장애 격리**: 드라이버와 서비스가 유저 스페이스 프로세스로 실행되어 드라이버 크래시가 시스템 전체에 영향을 주지 않음
- **능력(Capability) 기반 보안**: IPC 수준에서 세밀한 접근 제어
- **POSIX 호환**: 기존 유닉스 애플리케이션을 수정 없이 실행 가능

## 핵심 설계 목표

| 목표 | 접근 방식 |
|------|----------|
| **안정성** | Rust의 소유권 모델로 데이터 경합과 메모리 손상 제거. 커널 전반에 걸친 `Result<T, E>` 기반 에러 전파 |
| **보안** | 능력(Capability) 기반 접근 제어, 권한 분리, 최소 신뢰 컴퓨팅 기반(TCB) |
| **확장성** | 모듈식 마이크로커널 — 재부팅 없이 OS 서비스 추가 또는 교체 가능. 유저 스페이스 드라이버 및 파일 시스템 |
| **성능** | 제로 코스트 추상화, 락프리 자료구조, 효율적인 동기/비동기 IPC, 최소 컨텍스트 스위치 |

## 아키텍처

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

## 프로젝트 구조

```
oncrix/
├── crates/
│   ├── kernel/          # 마이크로커널 코어 (스케줄러, IPC, 메모리 관리)
│   ├── hal/             # 하드웨어 추상화 계층 (x86_64, aarch64, riscv64)
│   ├── bootloader/      # 부트 프로토콜 및 초기 초기화
│   ├── drivers/         # 유저 스페이스 디바이스 드라이버 프레임워크
│   ├── vfs/             # 가상 파일 시스템
│   ├── process/         # 프로세스 및 스레드 관리
│   ├── ipc/             # 프로세스 간 통신 프리미티브
│   ├── mm/              # 메모리 관리 (가상 메모리, 페이지 할당기)
│   ├── syscall/         # POSIX 호환 시스템 콜 인터페이스
│   └── lib/             # 공유 유틸리티 및 에러 타입
├── docs/                # 문서 및 개발자 위키
├── .github/             # CI/CD 워크플로우 및 이슈 템플릿
├── Cargo.toml           # 워크스페이스 설정
├── CONTRIBUTING.md      # 기여 가이드라인
├── CHANGELOG.md         # 변경 이력
├── SECURITY.md          # 보안 정책
├── CODE_OF_CONDUCT.md   # 커뮤니티 행동 강령
├── LICENSE              # Apache License 2.0
└── README.md
```

## 크레이트 의존성 그래프

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

## 기술 스택

- **언어**: Rust 1.85+ (Edition 2024)
- **빌드 시스템**: Cargo 워크스페이스
- **타겟 아키텍처**: x86_64 (주요), aarch64 (예정), riscv64 (예정)
- **라이선스**: Apache-2.0
- **CI/CD**: GitHub Actions

## 시작하기

### 사전 요구사항

- Rust 1.85+ (`#![no_std]` 커널 개발을 위해 nightly 권장)
- QEMU (가상 머신에서 OS 테스트용)

### 빌드

```bash
cargo build --workspace
```

### 검증

```bash
cargo fmt --all -- --check && cargo clippy --workspace -- -D warnings && cargo build --workspace
```

## 로드맵

### Phase 1: 기반 구축
- [x] 프로젝트 구조 및 워크스페이스 설정
- [ ] 기본 부트로더 (UEFI/Multiboot2)
- [ ] 시리얼 콘솔 출력
- [ ] 물리 메모리 관리자 (비트맵 할당기)
- [ ] 가상 메모리 (페이지 테이블)

### Phase 2: 코어 커널
- [ ] 커널 힙 할당기
- [ ] 인터럽트 처리 (IDT, APIC)
- [ ] 타이머 (PIT/HPET/APIC timer)
- [ ] 기본 스케줄러 (라운드 로빈)
- [ ] 컨텍스트 스위칭

### Phase 3: IPC & 프로세스
- [ ] 동기 IPC (send/receive/reply)
- [ ] 비동기 IPC (알림)
- [ ] 프로세스 생성 및 소멸
- [ ] ELF 로더
- [ ] 유저 스페이스 실행

### Phase 4: 서비스
- [ ] VFS 계층
- [ ] RAM 디스크 파일 시스템
- [ ] 디바이스 드라이버 프레임워크
- [ ] 콘솔 드라이버
- [ ] 키보드/마우스 드라이버

### Phase 5: POSIX 호환
- [ ] POSIX 시스템 콜 계층
- [ ] 시그널 처리
- [ ] 파이프 및 FIFO
- [ ] fork/exec/wait
- [ ] 기본 셸

## 기여하기

가이드라인은 [CONTRIBUTING.md](../CONTRIBUTING.md) ([한국어](CONTRIBUTING.ko.md))를 참고하세요.

## 라이선스

Apache License 2.0에 따라 라이선스됩니다. 자세한 내용은 [LICENSE](../LICENSE)를 참고하세요.

```
Copyright 2026 ONCRIX Contributors
SPDX-License-Identifier: Apache-2.0
```
