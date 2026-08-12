#!/usr/bin/env bash
# Copyright 2026 ONCRIX Contributors
# SPDX-License-Identifier: Apache-2.0
#
# ONCRIX host unit-test runner.
#
# Runs each crate's `#[cfg(test)]` modules natively on the host triple.
#
# `cargo test --workspace` from the repo root does NOT work: `.cargo/config.toml`
# pins the default target to `x86_64-unknown-none`, and libtest needs std. Each
# crate is therefore built for the host triple explicitly, one at a time.
#
# Usage: ./scripts/run-tests.sh [extra cargo args...]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="${ONCRIX_PROJECT_DIR:-$(dirname "$SCRIPT_DIR")}"
cd "$PROJECT_DIR"

HOST="$(rustc --print host-tuple 2>/dev/null || rustc --print target-triple)"

# Kernel structures are fixed-capacity inline tables (`const X: Option<Big> =
# None; [X; N]` is the project-wide idiom). Building one inside a test overflows
# libtest's default 2 MiB thread stack, which aborts the whole binary with no
# attribution to a test name. 256 MiB clears every test in the tree today.
export RUST_MIN_STACK="${RUST_MIN_STACK:-268435456}"

# Tests that fail or crash today.
#
# This list is currently EMPTY: every test in the runner passes, across all ten
# crates. It exists so a genuinely broken test can be quarantined *with its root
# cause named*, not so a red build can be made green. Adding an entry without a
# diagnosis, or to avoid fixing a defect, defeats the purpose of running the
# suite at all.
skips_for() {
    case "$1" in
    esac
}

CRATES=(
    oncrix-lib
    oncrix-hal
    oncrix-mm
    oncrix-ipc
    oncrix-vfs
    oncrix-process
    oncrix-drivers
    oncrix-kernel
    oncrix-bootloader
    oncrix-syscall
)

total_pass=0
total_skip=0
failed_crates=()

echo "[run-tests] host triple: $HOST"
echo "[run-tests] RUST_MIN_STACK: $RUST_MIN_STACK"

for crate in "${CRATES[@]}"; do
    skip_args=()
    n_skip=0
    while IFS= read -r t; do
        [[ -z "$t" ]] && continue
        skip_args+=(--skip "$t")
        n_skip=$((n_skip + 1))
    done < <(skips_for "$crate")

    log="$(mktemp)"
    cargo test -p "$crate" --target "$HOST" --lib "$@" -- \
        "${skip_args[@]+"${skip_args[@]}"}" >"$log" 2>&1
    status=$?

    result="$(grep -E '^test result:' "$log" | tail -1)"
    passed="$(echo "$result" | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+')"
    total_pass=$((total_pass + ${passed:-0}))
    total_skip=$((total_skip + n_skip))

    if [[ $status -eq 0 ]]; then
        printf '[run-tests] %-18s ok      %s passed' "$crate" "${passed:-0}"
        [[ $n_skip -gt 0 ]] && printf ' (%s known-bad skipped)' "$n_skip"
        printf '\n'
    else
        printf '[run-tests] %-18s FAILED  %s\n' "$crate" "$result"
        sed -n '/^failures:$/,$p' "$log" | head -40
        grep -E 'stack overflow|SIGSEGV|SIGABRT|^error' "$log" | head -10
        failed_crates+=("$crate")
    fi
    rm -f "$log"
done

echo "[run-tests] ─────────────────────────────────────"
echo "[run-tests] total: $total_pass passed, $total_skip known-bad skipped"

if [[ ${#failed_crates[@]} -gt 0 ]]; then
    echo "[run-tests] FAILED crates: ${failed_crates[*]}"
    exit 1
fi

echo "[run-tests] All host unit tests passed."
