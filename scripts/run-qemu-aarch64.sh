#!/usr/bin/env bash
# Copyright 2026 ONCRIX Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Run the ONCRIX kernel in QEMU (aarch64, `virt` machine).
# Usage: ./scripts/run-qemu-aarch64.sh [--release]
#
# The kernel targets the GICv3 interrupt controller, so `gic-version=3`
# is required (the `virt` machine defaults to GICv2, which has no
# redistributor and faults `init_gic`). Serial (PL011 @ 0x0900_0000) is
# routed to stdout. Expected output:
#   [ONCRIX/aarch64] Kernel booting...
#   [ONCRIX/aarch64] PL011 UART initialized (115200 8N1)
#   [ONCRIX/aarch64] Heap initialized (16 MiB)
#   [ONCRIX/aarch64] GICv3 initialized
#   [ONCRIX/aarch64] Generic timer armed (10 ms)
#   [ONCRIX/aarch64] All early initialization complete.
#   [ONCRIX/aarch64] Entering halt loop.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TARGET="aarch64-unknown-none"

PROFILE="debug"
if [[ "${1:-}" == "--release" ]]; then
    PROFILE="release"
    shift
    cargo build -p oncrix-kernel --bin oncrix-kernel --target "$TARGET" --release
else
    cargo build -p oncrix-kernel --bin oncrix-kernel --target "$TARGET"
fi

KERNEL="$PROJECT_DIR/target/$TARGET/$PROFILE/oncrix-kernel"

if [[ ! -f "$KERNEL" ]]; then
    echo "Error: kernel binary not found at $KERNEL"
    exit 1
fi

exec qemu-system-aarch64 \
    -M virt,gic-version=3 \
    -cpu cortex-a72 \
    -m 512M \
    -nographic \
    -monitor none \
    -no-reboot \
    -kernel "$KERNEL" \
    "$@"
