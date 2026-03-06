# Project Backup Toolkit

프로젝트 전체를 암호화 백업/복원하고, git 커밋 흔적을 삭제하는 도구.

퍼블릭 GitHub 저장소에 올려도 안전하도록 AES-256-CBC로 암호화하며,
GitHub 100MB 제한에 맞춰 자동 분할합니다.

## 스크립트

| 스크립트 | 용도 |
|----------|------|
| `archive.sh` | 프로젝트 전체 → 암호화 분할 백업 생성 |
| `restore.sh` | 기존 프로젝트 삭제 후 백업으로 전체 교체 |
| `purge-history.sh` | git 히스토리에서 tmp-igbkp/ 전체 흔적 완전 제거 |
| `legacy-verify.sh` | 구버전 백업에서 누락된 파일 분석 (읽기 전용) |
| `legacy-mig.sh` | 구버전 백업 누락 파일 복구 + 최신 프로젝트 동기화 |

## 사용법

```bash
# 1. 백업 생성 (비밀번호는 대화형 입력)
./tmp-igbkp/archive.sh

# 2. GitHub에 커밋 & 푸시
git add tmp-igbkp/output/
git commit -m "chore: add encrypted project backup"
git push

# 3. 다른 환경(Codespaces 등)에서 복원
git clone <repo>
./tmp-igbkp/restore.sh

# 4. 복원 완료 후 커밋 흔적 제거
./tmp-igbkp/purge-history.sh
```

## 백업 범위

- 프로젝트 디렉토리 내 **모든 파일** (`.git/` 포함, 파일 + 심볼릭 링크)
- 제외: `tmp-igbkp/`만

## 다른 프로젝트에서 사용

`tmp-igbkp/` 폴더를 통째로 복사하면 어떤 git 프로젝트에서든 바로 사용 가능합니다.
프로젝트 종속 코드가 없으며, 상위 디렉토리 기준으로 자동 동작합니다.

```bash
cp -r tmp-igbkp/ /path/to/other-project/tmp-igbkp/
```

## 보안

- **비밀번호**: 항상 대화형 입력 (CLI 인자 불가 — shell history 노출 방지)
- **암호화**: AES-256-CBC (OpenSSL)
- **키 유도**: PBKDF2, 600,000 iterations (brute-force 방어)
- **비밀번호 전달**: fd (file descriptor) 방식 (`/proc/PID/cmdline` 노출 방지)
- **분할**: GitHub 100MB 제한 대응 (95MB 단위 자동 분할)
- **무결성**: SHA-256 체크섬 검증 (manifest.txt)
