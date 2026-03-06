# ONCRIX Verification Checklist

Pre-commit quality assurance checklist for the ONCRIX operating system.

## Quick Verification

```bash
cargo fmt --all -- --check && cargo clippy --workspace -- -D warnings && cargo build --workspace
```

---

## 1. Build & Toolchain

- [ ] `cargo build --workspace` succeeds without errors
- [ ] `cargo clippy --workspace -- -D warnings` passes with zero warnings
- [ ] `cargo fmt --all -- --check` reports no formatting issues
- [ ] `cargo build --workspace` succeeds
- [ ] Cross-compilation for target architectures builds successfully

## 2. Security

- [ ] No `unwrap()` or `expect()` in production code paths
- [ ] All `unsafe` blocks have `// SAFETY:` comments documenting invariants
- [ ] `unsafe` blocks are wrapped in safe abstractions with documented preconditions
- [ ] User-space pointers are validated before kernel-space dereferencing
- [ ] No hardcoded credentials, keys, or secrets in source code
- [ ] Input validation at all system boundaries (syscalls, IPC messages, driver interfaces)
- [ ] Capability checks are enforced before privileged operations
- [ ] No raw pointer arithmetic without bounds checking
- [ ] Interrupt handlers do not access user-space memory directly

## 3. Stability

- [ ] No infinite loops without explicit break conditions or timeout mechanisms
- [ ] Integer overflow handled (use `checked_*`/`wrapping_*`/`saturating_*` arithmetic)
- [ ] No panics in interrupt context or with interrupts disabled
- [ ] Graceful error handling for resource exhaustion (OOM, FD limits, process limits)
- [ ] All error paths properly clean up allocated resources (no leaks)
- [ ] Deadlock-free lock ordering is maintained (document lock hierarchy)
- [ ] Stack overflow protection for kernel threads

## 4. Privacy & Hygiene

- [ ] No hardcoded file paths or system-specific paths
- [ ] No personal information or identifiers in code or comments
- [ ] No debug print statements left in production code
- [ ] No `TODO`/`FIXME` without an associated issue number
- [ ] No commented-out code blocks (remove or create an issue)

## 5. Performance

- [ ] Hot paths avoid heap allocation where possible
- [ ] Lock hold times are minimized (no I/O while holding locks)
- [ ] IPC message sizes are bounded and validated
- [ ] No O(n^2) or worse algorithms in critical paths without documented justification
- [ ] DMA buffers are properly aligned to hardware requirements
- [ ] Spinlocks are used only for short critical sections
- [ ] Memory-mapped I/O uses volatile reads/writes

## 6. Documentation

- [ ] All public types, traits, and functions have `///` doc comments
- [ ] Architecture-specific behavior is documented with `#[cfg]` annotations explained
- [ ] POSIX compatibility notes are included where relevant
- [ ] README and docs are updated if public API changes
- [ ] Safety invariants are documented for all `unsafe` abstractions
- [ ] Module-level `//!` documentation describes the module's purpose

## 7. Code Quality

- [ ] Error types implement `Display` and `Debug`
- [ ] No dead code (unused functions, imports, variables)
- [ ] Type safety enforced: newtypes for distinct concepts (PID, TID, FD, PhysAddr, VirtAddr)
- [ ] Constants preferred over magic numbers
- [ ] License header present: `// Copyright 2026 ONCRIX Contributors` + `// SPDX-License-Identifier: Apache-2.0`
- [ ] `#![no_std]` used for all kernel-space crates
- [ ] Naming follows Rust conventions (snake_case functions, CamelCase types)

---

## Known Issues

_No known issues at this time._
