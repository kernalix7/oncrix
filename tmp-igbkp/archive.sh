#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# archive.sh — 프로젝트 전체 암호화 백업
#
# 용도: 이 스크립트가 위치한 폴더를 제외한 프로젝트의 모든 파일(.git 포함)을
#       AES-256-CBC로 암호화 후 분할하여 GitHub 퍼블릭 저장소에
#       안전하게 업로드할 수 있게 합니다.
#
# 사용법:
#   ./tmp-igbkp/archive.sh
#
# 출력:
#   output/ 폴더에 분할된 암호화 파일 + manifest.txt 생성
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SPLIT_SIZE="95M"  # GitHub 100MB 제한 → 95MB 여유

# PROJECT_ROOT 탐색 (.git 디렉토리를 찾을 때까지 상위로)
PROJECT_ROOT="$SCRIPT_DIR"
while [[ "$PROJECT_ROOT" != "/" ]]; do
    [[ -d "$PROJECT_ROOT/.git" ]] && break
    PROJECT_ROOT="$(dirname "$PROJECT_ROOT")"
done

# 툴킷 폴더명 (PROJECT_ROOT 기준 상대경로)
TOOLKIT_REL="${SCRIPT_DIR#$PROJECT_ROOT/}"
OUTPUT_DIR="$SCRIPT_DIR/output"

# 색상
RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'

log()  { echo -e "${GREEN}[archive]${NC} $*"; }
err()  { echo -e "${RED}[error]${NC} $*" >&2; }

# sha256 래퍼 (macOS: shasum, Linux: sha256sum)
if command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum "$@"; }
elif command -v shasum >/dev/null 2>&1; then
    sha256() { shasum -a 256 "$@"; }
else
    err "sha256sum 또는 shasum이 필요합니다."; exit 1
fi

# GNU split 확인 (macOS: gsplit 필요)
if command -v gsplit >/dev/null 2>&1; then
    SPLIT_CMD="gsplit"
elif split --version 2>&1 | grep -q GNU 2>/dev/null; then
    SPLIT_CMD="split"
else
    err "GNU split이 필요합니다. macOS: brew install coreutils"; exit 1
fi

# 기본 의존성
for cmd in tar openssl; do
    command -v "$cmd" >/dev/null 2>&1 || { err "'$cmd' 명령어가 필요합니다."; exit 1; }
done

if [[ ! -d "$PROJECT_ROOT/.git" ]]; then
    err "git 저장소를 찾을 수 없습니다."
    exit 1
fi

# 비밀번호 입력 (반드시 대화형)
if [[ $# -gt 0 ]]; then
    err "비밀번호는 명령줄 인자로 받지 않습니다 (shell history 노출 방지)."
    err "사용법: ./$TOOLKIT_REL/archive.sh"
    exit 1
fi

echo -n "암호화 비밀번호 입력: "
read -rs PASSWORD
echo
echo -n "비밀번호 확인: "
read -rs PASSWORD_CONFIRM
echo
if [[ "$PASSWORD" != "$PASSWORD_CONFIRM" ]]; then
    err "비밀번호가 일치하지 않습니다."
    exit 1
fi

if [[ ${#PASSWORD} -lt 8 ]]; then
    err "비밀번호는 최소 8자 이상이어야 합니다."
    exit 1
fi

# 준비
cd "$PROJECT_ROOT"
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

TMPDIR_WORK="$SCRIPT_DIR/.work"
rm -rf "$TMPDIR_WORK"
mkdir -p "$TMPDIR_WORK"
trap 'rm -rf "$TMPDIR_WORK"' EXIT

# 프로젝트 전체 파일 수집 (툴킷 폴더만 제외)
log "프로젝트 파일 수집 중..."
FILE_COUNT=$(find . -not -path "./$TOOLKIT_REL/*" -not -path "./$TOOLKIT_REL" \
                    \( -type f -o -type l \) | wc -l)

if [[ "$FILE_COUNT" -eq 0 ]]; then
    log "백업할 파일이 없습니다."
    exit 0
fi

log "아카이브 대상: $FILE_COUNT 개 파일"

# tar 생성
TAR_FILE="$TMPDIR_WORK/project.tar.gz"
log "tar.gz 생성 중..."
tar czf "$TAR_FILE" \
    --exclude="./$TOOLKIT_REL" \
    .

TAR_SIZE=$(du -h "$TAR_FILE" | cut -f1)
log "tar.gz 크기: $TAR_SIZE"

# AES-256-CBC 암호화
ENC_FILE="$TMPDIR_WORK/project.tar.gz.enc"
log "AES-256-CBC 암호화 중 (PBKDF2, 600k iterations)..."
openssl enc -aes-256-cbc -salt -pbkdf2 -iter 600000 \
    -in "$TAR_FILE" -out "$ENC_FILE" \
    -pass "fd:3" 3<<< "$PASSWORD"

ENC_SIZE=$(du -h "$ENC_FILE" | cut -f1)
log "암호화 파일 크기: $ENC_SIZE"

# 분할
log "분할 중 (단위: $SPLIT_SIZE)..."
$SPLIT_CMD -b "$SPLIT_SIZE" -d --additional-suffix=".part" "$ENC_FILE" "$OUTPUT_DIR/igbkp_"

# 타임스탬프 (GNU/BSD 호환)
if date -Iseconds >/dev/null 2>&1; then
    TIMESTAMP=$(date -Iseconds)
else
    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S%z")
fi

# manifest 생성
MANIFEST="$OUTPUT_DIR/manifest.txt"
{
    echo "# project full backup manifest"
    echo "# created: $TIMESTAMP"
    echo "# project: $(basename "$PROJECT_ROOT")"
    echo "# encryption: AES-256-CBC, PBKDF2, 600000 iterations"
    echo "# split_size: $SPLIT_SIZE"
    echo "# original_tar_size: $TAR_SIZE"
    echo "# encrypted_size: $ENC_SIZE"
    echo "# file_count: $FILE_COUNT"
    echo "#"
    echo "# SHA-256 checksums:"
    for f in "$OUTPUT_DIR"/igbkp_*.part; do
        (cd "$OUTPUT_DIR" && sha256 "$(basename "$f")")
    done
} > "$MANIFEST"

# 결과 출력
PART_COUNT=$(ls "$OUTPUT_DIR"/igbkp_*.part 2>/dev/null | wc -l)
log "완료!"
echo ""
echo "=========================================="
echo " 아카이브 생성 완료"
echo "=========================================="
echo " 출력 위치: $OUTPUT_DIR/"
echo " 파일 수:   ${FILE_COUNT}개"
echo " 분할 파일: ${PART_COUNT}개"
echo ""
echo " 복원: ./$TOOLKIT_REL/restore.sh"
echo "=========================================="
