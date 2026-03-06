# Administration Guide

How to build, boot, and configure ONCRIX.

## Contents

- [Building](building.md) — Toolchain setup and build instructions
- [Running](running.md) — QEMU, real hardware, debugging
- [Configuration](configuration.md) — Kernel parameters and options

---

## Quick Start

### Prerequisites

- Rust nightly toolchain (pinned in `rust-toolchain.toml`)
- `x86_64-unknown-none` target
- QEMU (for testing)
- GRUB or compatible Multiboot2 bootloader

### Build

```bash
cd oncrix

# Full verification (recommended)
cargo fmt --all -- --check && \
cargo clippy --workspace -- -D warnings && \
cargo build --workspace

# Quick build only
cargo build --workspace
```

### Run in QEMU

```bash
./scripts/run-qemu.sh
```

This starts QEMU with:
- `-kernel` pointing to the kernel ELF binary
- `-serial stdio` for serial console output
- No display (headless)

### Expected Boot Output

```
[ONCRIX] Kernel booting...
[ONCRIX] Serial console initialized (COM1, 115200 8N1)
[ONCRIX] GDT loaded
[ONCRIX] IDT loaded (5 exception handlers)
[ONCRIX] Kernel heap initialized (256 KiB)
[ONCRIX] PIC remapped (IRQ 32-47)
[ONCRIX] PIT initialized (100 Hz)
[ONCRIX] Interrupts enabled
[ONCRIX] Scheduler initialized (idle thread)
```
