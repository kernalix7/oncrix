# ONCRIX 기여 가이드

[English](../CONTRIBUTING.md) | **한국어**

ONCRIX에 기여해 주셔서 감사합니다!

## 개발 환경 설정

### 사전 요구사항

- **Rust 1.85+** (`#![no_std]` 기능을 위해 nightly 권장)
- **QEMU 7.0+** (시스템 수준 테스트용)
- **Git** (버전 관리)

### 시작하기

```bash
git clone https://github.com/kernalix7/oncrix.git
cd oncrix
cargo build --workspace
```

## 작업 흐름

1. 저장소를 **포크**합니다
2. 기능 브랜치를 **생성**합니다: `git checkout -b feature/my-change`
3. [VERIFICATION_CHECKLIST.md](VERIFICATION_CHECKLIST.md)의 코딩 규칙을 따라 변경 사항을 **구현**합니다
4. 변경 사항을 **검증**합니다: `cargo fmt --all -- --check && cargo clippy --workspace -- -D warnings && cargo build --workspace`
5. [Conventional Commits](https://www.conventionalcommits.org/)를 사용하여 **커밋**합니다
6. **푸시**하고 풀 리퀘스트를 엽니다

## 커밋 규칙

[Conventional Commits](https://www.conventionalcommits.org/) 형식을 사용합니다:

| 접두사 | 용도 |
|--------|------|
| `feat:` | 새 기능 |
| `fix:` | 버그 수정 |
| `docs:` | 문서만 변경 |
| `refactor:` | 코드 리팩토링 (동작 변경 없음) |
| `test:` | 테스트 추가 또는 업데이트 |
| `chore:` | 빌드, CI, 도구 변경 |

예시: `feat(ipc): 동기 send/receive 구현`

## 풀 리퀘스트 체크리스트

- [ ] 변경 사항과 그 이유에 대한 명확한 설명
- [ ] 새 기능에 대한 테스트 추가 또는 업데이트
- [ ] `cargo fmt --all -- --check` 통과
- [ ] `cargo clippy --workspace -- -D warnings` 통과
- [ ] `cargo build --workspace` 성공
- [ ] 공개 API에 `///` 주석으로 문서화
- [ ] 프로덕션 코드 경로에 `unwrap()`/`expect()` 없음
- [ ] 모든 `unsafe` 블록에 `// SAFETY:` 주석
- [ ] 새 파일에 라이선스 헤더 포함
- [ ] 공개 API 변경 시 README/docs 업데이트
- [ ] 하드코딩된 경로, 비밀, 개인 정보 없음

## 코드 리뷰

- 모든 풀 리퀘스트는 머지 전 최소 한 명의 리뷰 필요
- 깔끔한 이력을 위해 스쿼시 머지 선호
- 머지 전 CI 통과 필수

## 보안

보안 취약점을 발견하신 경우, 공개 이슈가 아닌
[GitHub Security Advisories](https://github.com/kernalix7/oncrix/security/advisories)를
통해 신고해 주세요.

## 라이선스

기여하시면 귀하의 기여가 Apache License 2.0에 따라 라이선스되는 것에 동의하게 됩니다.
