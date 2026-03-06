# Development Process

This section describes how ONCRIX is developed, the coding conventions,
and how to contribute.

## Contents

- [Coding Style](coding-style.md) — Rust conventions, naming, formatting
- [Contributing](contributing.md) — How to submit patches and PRs
- [Commit Messages](commit-messages.md) — Conventional Commits format
- [Code Review](code-review.md) — Review criteria and checklist

---

## Coding Style Summary

ONCRIX follows standard Rust conventions with these additions:

1. **`#![no_std]`** for all kernel-space crates
2. **`// SAFETY:`** comments on every `unsafe` block
3. **No `unwrap()`/`expect()`** in production code — use `?` propagation
4. **100-character line limit**
5. **Conventional Commits** — `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`
6. **Apache-2.0** license header on every source file

## Architecture Principles

1. **Minimal kernel** — Only scheduling, IPC, and memory management in Ring 0
2. **User-space services** — Drivers, VFS, networking run in Ring 3
3. **Message-passing IPC** — Primary inter-service communication
4. **Capability-based security** — Unforgeable access tokens
5. **POSIX at the edge** — Compatibility in user-space libraries, not kernel core
