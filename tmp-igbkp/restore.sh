#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# restore.sh — 암호화된 프로젝트 백업 복원
#
# 용도: archive.sh로 생성된 분할 암호화 파일을 복호화하여
#       기존 프로젝트를 삭제하고 백업으로 전체 교체합니다.
#
# 사용법:
#   ./tmp-igbkp/restore.sh              # 대화형 비밀번호 입력
#   ./tmp-igbkp/restore.sh --dry-run    # 파일 목록만 확인
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# PROJECT_ROOT 탐색
PROJECT_ROOT="$SCRIPT_DIR"
while [[ "$PROJECT_ROOT" != "/" ]]; do
    [[ -d "$PROJECT_ROOT/.git" ]] && break
    PROJECT_ROOT="$(dirname "$PROJECT_ROOT")"
done

TOOLKIT_REL="${SCRIPT_DIR#$PROJECT_ROOT/}"
OUTPUT_DIR="$SCRIPT_DIR/output"

# 색상
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

log()  { echo -e "${GREEN}[restore]${NC} $*"; }
err()  { echo -e "${RED}[error]${NC} $*" >&2; }

# sha256 래퍼
if command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum "$@"; }
elif command -v shasum >/dev/null 2>&1; then
    sha256() { shasum -a 256 "$@"; }
else
    err "sha256sum 또는 shasum이 필요합니다."; exit 1
fi

for cmd in cat openssl tar diff; do
    command -v "$cmd" >/dev/null 2>&1 || { err "'$cmd' 명령어가 필요합니다."; exit 1; }
done

if [[ ! -d "$PROJECT_ROOT/.git" ]]; then
    err "git 저장소를 찾을 수 없습니다."
    exit 1
fi

# 인자 파싱
DRY_RUN=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true; shift ;;
        *) err "알 수 없는 옵션: $1"; exit 1 ;;
    esac
done

# 분할 파일 존재 확인
PARTS=("$OUTPUT_DIR"/igbkp_*.part)
if [[ ! -f "${PARTS[0]}" ]]; then
    err "분할 파일을 찾을 수 없습니다: $OUTPUT_DIR/igbkp_*.part"
    exit 1
fi

log "${#PARTS[@]} 개 분할 파일 발견"

# 체크섬 검증
MANIFEST="$OUTPUT_DIR/manifest.txt"
if [[ -f "$MANIFEST" ]]; then
    log "체크섬 검증 중..."
    while IFS= read -r line; do
        [[ "$line" =~ ^# ]] && continue
        [[ -z "$line" ]] && continue
        expected=$(echo "$line" | awk '{print $1}')
        filename=$(echo "$line" | awk '{print $2}')
        if [[ -f "$OUTPUT_DIR/$filename" ]]; then
            actual=$(sha256 "$OUTPUT_DIR/$filename" | awk '{print $1}')
            if [[ "$expected" != "$actual" ]]; then
                err "체크섬 불일치: $filename"
                exit 1
            fi
        fi
    done < "$MANIFEST"
    log "체크섬 검증 통과"
fi

# 비밀번호 입력
echo -n "복호화 비밀번호 입력: "
read -rs PASSWORD
echo

TMPDIR_WORK="$SCRIPT_DIR/.work"
rm -rf "$TMPDIR_WORK"
mkdir -p "$TMPDIR_WORK"
CLEANUP=true
trap '[[ "$CLEANUP" == true ]] && rm -rf "$TMPDIR_WORK"' EXIT

# 복호화
ENC_FILE="$TMPDIR_WORK/project.tar.gz.enc"
TAR_FILE="$TMPDIR_WORK/project.tar.gz"

log "분할 파일 합치는 중..."
cat "${PARTS[@]}" > "$ENC_FILE"

log "복호화 중..."
if ! openssl enc -aes-256-cbc -d -salt -pbkdf2 -iter 600000 \
    -in "$ENC_FILE" -out "$TAR_FILE" \
    -pass "fd:3" 3<<< "$PASSWORD" 2>/dev/null; then
    err "복호화 실패. 비밀번호가 틀렸거나 파일이 손상되었습니다."
    exit 1
fi

log "복호화 성공"

# dry-run
if [[ "$DRY_RUN" == true ]]; then
    log "포함된 파일 목록 (dry-run):"
    tar tzf "$TAR_FILE" | head -100
    TOTAL=$(tar tzf "$TAR_FILE" | wc -l)
    echo "... 총 $TOTAL 개 항목"
    exit 0
fi

# 임시 디렉토리에 풀기 (비교용)
EXTRACT_DIR="$TMPDIR_WORK/extracted"
mkdir -p "$EXTRACT_DIR"
log "압축 해제 중..."
tar xzf "$TAR_FILE" -C "$EXTRACT_DIR" --no-same-owner 2>/dev/null || \
    tar xzf "$TAR_FILE" -C "$EXTRACT_DIR"

# 기존 프로젝트와 차이 비교
log "기존 프로젝트와 비교 중..."

DIFF_REPORT="$TMPDIR_WORK/diff_report.txt"
MODIFIED=0
NEW_FILES=0
DELETED=0

while IFS= read -r rel_path; do
    current="$PROJECT_ROOT/$rel_path"
    backup="$EXTRACT_DIR/$rel_path"
    if [[ ! -e "$current" ]]; then
        echo "[새 파일]  $rel_path" >> "$DIFF_REPORT"
        ((NEW_FILES++)) || true
    elif [[ -f "$current" && -f "$backup" ]]; then
        if ! diff -q "$current" "$backup" >/dev/null 2>&1; then
            echo "[변경됨]  $rel_path" >> "$DIFF_REPORT"
            ((MODIFIED++)) || true
        fi
    fi
done < <(cd "$EXTRACT_DIR" && find . \( -type f -o -type l \) 2>/dev/null | sed 's|^\./||')

while IFS= read -r rel_path; do
    if [[ ! -e "$EXTRACT_DIR/$rel_path" ]]; then
        echo "[삭제됨]  $rel_path" >> "$DIFF_REPORT"
        ((DELETED++)) || true
    fi
done < <(cd "$PROJECT_ROOT" && find . -not -path "./$TOOLKIT_REL/*" -not -path "./$TOOLKIT_REL" \
    \( -type f -o -type l \) 2>/dev/null | sed 's|^\./||')

TOTAL_DIFF=$((MODIFIED + NEW_FILES + DELETED))

if [[ "$TOTAL_DIFF" -eq 0 ]]; then
    log "기존 프로젝트와 백업이 동일합니다. 복원할 내용이 없습니다."
    exit 0
fi

# 차이 경고
echo ""
echo -e "${YELLOW}══════════════════════════════════════════${NC}"
echo -e "${YELLOW} 기존 프로젝트와 백업 간 차이 발견${NC}"
echo -e "${YELLOW}══════════════════════════════════════════${NC}"
echo ""
echo -e "  변경된 파일:  ${CYAN}${MODIFIED}${NC}개"
echo -e "  새로운 파일:  ${CYAN}${NEW_FILES}${NC}개"
echo -e "  삭제될 파일:  ${CYAN}${DELETED}${NC}개"
echo ""

if [[ -f "$DIFF_REPORT" ]]; then
    head -30 "$DIFF_REPORT"
    REPORT_LINES=$(wc -l < "$DIFF_REPORT")
    if [[ "$REPORT_LINES" -gt 30 ]]; then
        echo "  ... 외 $((REPORT_LINES - 30))개"
    fi
fi

echo ""
echo -e "${RED} 기존 프로젝트를 삭제하고 백업으로 전체 교체합니다.${NC}"
echo -n " 계속하시겠습니까? (yes/no): "
read -r answer
if [[ "$answer" != "yes" ]]; then
    log "취소됨."
    exit 0
fi

# 삭제 시작 — 이후 실패하면 추출 데이터를 보존해야 함
CLEANUP=false

cd "$PROJECT_ROOT"
TOOLKIT_NAME="$(basename "$SCRIPT_DIR")"
log "기존 파일 삭제 중 ($TOOLKIT_NAME/ 제외)..."
find . -mindepth 1 -maxdepth 1 -not -name "$TOOLKIT_NAME" -exec rm -rf {} +

log "백업 파일 복원 중..."
cp -a "$EXTRACT_DIR"/. "$PROJECT_ROOT"/

RESTORED=$(cd "$EXTRACT_DIR" && find . \( -type f -o -type l \) | wc -l)

# 복원 성공 — 이제 정리 가능
CLEANUP=true
log "완료! ${RESTORED}개 파일 복원됨 (전체 교체)"
