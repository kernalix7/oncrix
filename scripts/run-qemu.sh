#!/usr/bin/env bash
# Copyright 2026 ONCRIX Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Run ONCRIX kernel in QEMU (x86_64).
# Usage: ./scripts/run-qemu.sh [--release]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

PROFILE="debug"
if [[ "${1:-}" == "--release" ]]; then
    PROFILE="release"
    cargo build --workspace --release
else
    cargo build --workspace
fi

KERNEL="$PROJECT_DIR/target/x86_64-unknown-none/$PROFILE/oncrix-kernel"

if [[ ! -f "$KERNEL" ]]; then
    echo "Error: kernel binary not found at $KERNEL"
    exit 1
fi

exec qemu-system-x86_64 \
    -kernel "$KERNEL" \
    -serial stdio \
    -display none \
    -no-reboot \
    -m 128M \
    -cpu qemu64 \
    "$@"
