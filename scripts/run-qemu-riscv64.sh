#!/usr/bin/env bash
# Copyright 2026 ONCRIX Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Run the ONCRIX kernel in QEMU (riscv64, `virt` machine).
# Usage: ./scripts/run-qemu-riscv64.sh [--release]
#
# The kernel uses the NS16550 UART (@ 0x1000_0000) and PLIC (@ 0x0C00_0000)
# that the `virt` machine provides. `-bios default` boots via OpenSBI in
# M-mode, which then enters the kernel in S-mode. Serial is on stdout.
#
# Requires qemu-system-riscv64 (part of the `qemu-system-misc` package on
# Debian/Ubuntu, `qemu` on Arch).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TARGET="riscv64gc-unknown-none-elf"

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

exec qemu-system-riscv64 \
    -M virt \
    -m 512M \
    -nographic \
    -monitor none \
    -no-reboot \
    -bios default \
    -kernel "$KERNEL" \
    "$@"
