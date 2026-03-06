#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# purge-history.sh — git 히스토리에서 아카이브 흔적 완전 제거
#
# 용도: archive.sh로 만든 파일을 git에 커밋했다가, 이후 그 흔적을
#       로컬 + 리모트에서 완전히 삭제합니다.
#
# 동작:
#   1. git filter-repo로 tmp-igbkp/ 관련 커밋을 히스토리에서 제거
#   2. 리모트에 force push
#
# 사용법:
#   ./tmp-igbkp/purge-history.sh                    # 대화형 확인
#   ./tmp-igbkp/purge-history.sh --confirm          # 확인 스킵
#   ./tmp-igbkp/purge-history.sh --path "경로"      # 커스텀 경로 지정
#
# ⚠️ 주의: force push가 포함된 파괴적 작업입니다.
#    다른 협업자가 있으면 반드시 사전 공유하세요.
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# PROJECT_ROOT 탐색
PROJECT_ROOT="$SCRIPT_DIR"
while [[ "$PROJECT_ROOT" != "/" ]]; do
    [[ -d "$PROJECT_ROOT/.git" ]] && break
    PROJECT_ROOT="$(dirname "$PROJECT_ROOT")"
done

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

log()  { echo -e "${GREEN}[purge]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }
err()  { echo -e "${RED}[error]${NC} $*" >&2; }

CONFIRM=false
PURGE_PATH="tmp-igbkp"
REMOTE="origin"
BRANCH=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --confirm) CONFIRM=true; shift ;;
        --path) PURGE_PATH="$2"; shift 2 ;;
        --remote) REMOTE="$2"; shift 2 ;;
        --branch) BRANCH="$2"; shift 2 ;;
        *) err "알 수 없는 옵션: $1"; exit 1 ;;
    esac
done

cd "$PROJECT_ROOT"

# 현재 브랜치 감지
if [[ -z "$BRANCH" ]]; then
    BRANCH=$(git rev-parse --abbrev-ref HEAD)
fi

# git filter-repo 또는 git filter-branch 사용 가능 확인
USE_FILTER_REPO=false
if command -v git-filter-repo >/dev/null 2>&1; then
    USE_FILTER_REPO=true
fi

# 해당 경로가 히스토리에 존재하는지 확인
COMMITS_WITH_PATH=$(git log --all --oneline -- "$PURGE_PATH" 2>/dev/null | wc -l)
if [[ "$COMMITS_WITH_PATH" -eq 0 ]]; then
    log "'$PURGE_PATH' 경로가 git 히스토리에 없습니다. 작업 불필요."
    exit 0
fi

log "히스토리에서 '$PURGE_PATH' 관련 커밋 ${COMMITS_WITH_PATH}개 발견"

# 경고 & 확인
if [[ "$CONFIRM" != true ]]; then
    echo ""
    echo -e "${RED}══════════════════════════════════════════${NC}"
    echo -e "${RED} ⚠️  경고: 파괴적 작업입니다!${NC}"
    echo -e "${RED}══════════════════════════════════════════${NC}"
    echo ""
    echo " 다음 작업이 수행됩니다:"
    echo "   1. git 히스토리에서 '$PURGE_PATH' 경로 완전 제거"
    echo "   2. $REMOTE/$BRANCH에 force push"
    echo ""
    echo " 관련 커밋:"
    git log --all --oneline -- "$PURGE_PATH" | head -10
    echo ""
    echo -n "계속하시겠습니까? (yes/no): "
    read -r answer
    if [[ "$answer" != "yes" ]]; then
        log "취소됨."
        exit 0
    fi
fi

# 백업: rewrite 전 커밋 해시 저장 (filter-repo/filter-branch가 모든 브랜치를 rewrite하므로)
BACKUP_SHA=$(git rev-parse HEAD)
log "현재 HEAD 저장: $BACKUP_SHA (복구 시: git reset --hard $BACKUP_SHA)"

# filter-repo는 remote를 삭제하므로, 미리 URL 저장
REMOTE_URL=""
if git remote get-url "$REMOTE" >/dev/null 2>&1; then
    REMOTE_URL=$(git remote get-url "$REMOTE")
    log "리모트 URL 저장: $REMOTE_URL"
fi

# 히스토리에서 경로 제거
if [[ "$USE_FILTER_REPO" == true ]]; then
    log "git filter-repo로 히스토리 정리 중..."
    git filter-repo --invert-paths --path "$PURGE_PATH" --force

    # filter-repo가 삭제한 remote 복원
    if [[ -n "$REMOTE_URL" ]]; then
        git remote add "$REMOTE" "$REMOTE_URL" 2>/dev/null || true
        log "리모트 복원: $REMOTE → $REMOTE_URL"
    fi
else
    log "git filter-branch로 히스토리 정리 중..."
    warn "git filter-repo 설치를 권장합니다 (pip install git-filter-repo)"

    git filter-branch --force --index-filter \
        "git rm -rf --cached --ignore-unmatch '$PURGE_PATH'" \
        --prune-empty --tag-name-filter cat -- --all 2>/dev/null || {
            # filter-branch가 실패하면 대안: BFG 없이 수동 처리
            err "filter-branch 실패. git-filter-repo를 설치하세요:"
            err "  pip install git-filter-repo"
            exit 1
        }

    # filter-branch 잔여물 정리
    rm -rf .git/refs/original/ 2>/dev/null || true
fi

# 리모트 존재 확인 후 force push
if git remote get-url "$REMOTE" >/dev/null 2>&1; then
    log "리모트($REMOTE)에 force push 중..."
    git push "$REMOTE" "$BRANCH" --force-with-lease 2>/dev/null || {
        warn "force-with-lease 실패, --force로 재시도..."
        git push "$REMOTE" "$BRANCH" --force
    }
    log "리모트 업데이트 완료"
else
    warn "리모트 '$REMOTE'이 설정되지 않음. 수동으로 push하세요:"
    warn "  git push <remote> $BRANCH --force"
fi

echo ""
echo "=========================================="
echo " 히스토리 정리 완료"
echo "=========================================="
echo " 제거 경로: $PURGE_PATH"
echo " 복구 명령: git reset --hard $BACKUP_SHA"
echo " 리모트: $REMOTE/$BRANCH"
echo ""
echo " 협업자에게 알려주세요:"
echo "   git fetch origin && git reset --hard origin/$BRANCH"
echo ""
echo " 문제 없으면 reflog 정리 (복구 불가능해짐):"
echo "   git reflog expire --expire=now --all && git gc --prune=now --aggressive"
echo "=========================================="
