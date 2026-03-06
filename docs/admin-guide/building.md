# Building ONCRIX

## Toolchain

ONCRIX requires a Rust nightly toolchain with the following components:

```toml
# rust-toolchain.toml
[toolchain]
channel = "nightly"
components = ["rustfmt", "clippy", "rust-src", "llvm-tools"]
targets = ["x86_64-unknown-none"]
```

The exact nightly version is pinned to ensure reproducible builds.

## Build Targets

| Target | Platform | Status |
|--------|----------|--------|
| `x86_64-unknown-none` | x86_64 bare metal | Primary |
| `aarch64-unknown-none` | ARM64 bare metal | Planned |
| `riscv64gc-unknown-none-elf` | RISC-V 64 | Planned |

## Build Commands

### Full Verification

```bash
cargo fmt --all -- --check && \
cargo clippy --workspace -- -D warnings && \
cargo build --workspace
```

This runs:
1. **Format check** — Ensure all code is properly formatted
2. **Clippy** — Static analysis with all warnings as errors
3. **Build** — Compile all 10 crates

### Release Build

```bash
cargo build --workspace --release
```

### Individual Crate

```bash
cargo build -p oncrix-kernel
cargo build -p oncrix-mm
```

## Build Configuration

### `.cargo/config.toml`

```toml
[build]
target = "x86_64-unknown-none"

[target.x86_64-unknown-none]
rustflags = [
    "-C", "code-model=kernel",
    "-C", "relocation-model=static",
]
```

### Linker Script

The kernel uses `crates/kernel/linker.ld` for higher-half mapping:

- Kernel loaded at `0xFFFFFFFF80000000` (virtual)
- Sections: `.multiboot2`, `.text`, `.rodata`, `.data`, `.bss`
- Physical load address: `0x100000` (1 MiB)

## Dependencies Policy

- **Kernel crates**: Zero external dependencies (`core` and `alloc` only)
- **User-space crates**: Minimal, well-maintained dependencies
- **License**: All deps must be Apache-2.0 compatible
- **Audit**: Run `cargo audit` regularly

## CI Pipeline

GitHub Actions runs on every push:

```yaml
jobs:
  check:
    - cargo fmt --all -- --check
    - cargo clippy --workspace -- -D warnings
    - cargo build --workspace
```
