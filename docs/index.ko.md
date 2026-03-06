# ONCRIX 커널 문서

[English](index.md)

ONCRIX 커널 문서에 오신 것을 환영합니다. 이 문서는 리눅스 커널 문서와
유사한 구조로 모든 서브시스템, API, 개발 가이드라인을 다룹니다.

**ONCRIX Is Not a Copy, Real Independent uniX**

---

## 문서 구조

### 개발자용

- [개발 프로세스](process/index.md) — 기여 방법, 코딩 스타일, 패치 워크플로우
- [Core API](core-api/index.md) — 커널 내부 API 레퍼런스
- [드라이버 API](driver-api/index.md) — ONCRIX 디바이스 드라이버 작성법

### 서브시스템 문서

- [메모리 관리](mm/index.md) — 물리/가상 메모리, 페이지 테이블, 할당기, CoW
- [프로세스 관리](process/process-model.md) — 프로세스, 스레드, 스케줄링, 시그널
- [스케줄러](scheduler/index.md) — 스케줄링 알고리즘과 선점
- [프로세스 간 통신](ipc/index.md) — 메시지 패싱, 채널, 엔드포인트
- [파일 시스템](filesystems/index.md) — VFS 레이어, ramfs, devfs, procfs
- [시스템 콜 인터페이스](core-api/syscalls.md) — POSIX 호환 syscall ABI

### 아키텍처별

- [x86_64](arch/x86_64/index.md) — GDT, IDT, APIC, SYSCALL/SYSRET, 페이징

### 관리

- [관리 가이드](admin-guide/index.md) — 빌드, 부팅, 설정
- [보안](security/index.md) — 케이퍼빌리티 모델, 권한 분리, 위협 모델

### 레퍼런스

- [아키텍처 개요](ARCHITECTURE.ko.md) — 전체 기술 아키텍처 문서
- [개발자 위키](DEVELOPER_WIKI.ko.md) — 크레이트별 가이드와 패턴
- [검증 체크리스트](VERIFICATION_CHECKLIST.ko.md) — 커밋 전 품질 체크
- [용어집](core-api/glossary.md) — ONCRIX 전용 용어

---

## 빠른 링크

| 하고 싶은 것 | 참고할 문서 |
|-------------|-----------|
| ONCRIX 빌드하기 | [관리 가이드 → 빌드](admin-guide/building.md) |
| 드라이버 작성하기 | [드라이버 API](driver-api/index.md) |
| IPC 이해하기 | [IPC → 설계](ipc/design.md) |
| syscall 추가하기 | [Core API → Syscalls](core-api/syscalls.md) |
| 메모리 레이아웃 이해하기 | [MM → 주소 공간](mm/address-space.md) |
| 코드 기여하기 | [프로세스 → 기여](process/contributing.md) |
