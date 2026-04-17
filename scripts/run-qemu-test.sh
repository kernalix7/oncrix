#!/usr/bin/env bash
# Copyright 2026 ONCRIX Contributors
# SPDX-License-Identifier: Apache-2.0
#
# ONCRIX QEMU boot integration test wrapper.
#
# Builds the boot-test harness and runs it. Exits 0 on success, 1 on failure.
#
# Usage: ./scripts/run-qemu-test.sh
#
# Environment:
#   ONCRIX_PROJECT_DIR  — override project root detection (optional)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="${ONCRIX_PROJECT_DIR:-$(dirname "$SCRIPT_DIR")}"
export ONCRIX_PROJECT_DIR="$PROJECT_DIR"

HARNESS_DIR="$PROJECT_DIR/tests/boot_tests"

echo "[run-qemu-test] Project dir: $PROJECT_DIR"
echo "[run-qemu-test] Building boot test harness..."

# Build from within the harness directory so the nested .cargo/config.toml
# (target = x86_64-unknown-linux-gnu) takes precedence over the workspace
# root's .cargo/config.toml (target = x86_64-unknown-none). Using
# --manifest-path from the repo root would pick up the kernel's no_std
# target and fail.
(cd "$HARNESS_DIR" && cargo build --quiet)

# The harness uses an explicit host target via .cargo/config.toml;
# cargo puts the binary under target/<host-triple>/debug/ not target/debug/.
HOST_TRIPLE="$(rustc --print host-tuple 2>/dev/null || rustc --print target-triple 2>/dev/null || echo "x86_64-unknown-linux-gnu")"
HARNESS_BIN="$HARNESS_DIR/target/$HOST_TRIPLE/debug/boot_test"

# Fallback to target/debug if the above isn't found (e.g. no explicit target set).
if [[ ! -x "$HARNESS_BIN" ]]; then
    HARNESS_BIN="$HARNESS_DIR/target/debug/boot_test"
fi

if [[ ! -x "$HARNESS_BIN" ]]; then
    echo "[run-qemu-test] ERROR: harness binary not found (searched $HARNESS_DIR/target/)"
    exit 1
fi

echo "[run-qemu-test] Running boot integration tests..."
exec "$HARNESS_BIN"
