# ONCRIX Coding Style

## Language

All ONCRIX code is written in Rust. No C, no assembly files (inline asm only).

## Formatting

- Run `cargo fmt` before every commit
- Maximum line length: 100 characters
- Use `rustfmt.toml` defaults (none overridden)

## Naming

| Item | Convention | Example |
|------|-----------|---------|
| Types, traits | `CamelCase` | `ProcessTable`, `FrameAllocator` |
| Functions, methods | `snake_case` | `alloc_pid()`, `handle_cow_fault()` |
| Constants | `UPPER_SNAKE_CASE` | `MAX_PROCESSES`, `PAGE_SIZE` |
| Modules | `snake_case` | `page_table`, `address_space` |
| Crates | `oncrix-name` | `oncrix-mm`, `oncrix-process` |
| Newtypes | `CamelCase` | `Pid(u64)`, `VirtAddr(u64)` |

## `unsafe` Rules

1. Minimize `unsafe` — wrap it in safe abstractions
2. Every `unsafe` block must have a `// SAFETY:` comment explaining:
   - What invariant must hold
   - Why we know it holds here
3. Prefer `unsafe fn` with documented preconditions over embedding
   `unsafe` blocks in safe functions
4. Use `#![forbid(unsafe_code)]` on crates that don't need it

### Example

```rust
/// # Safety
///
/// `pml4` must point to a valid, writable PML4 table.
pub unsafe fn map_page(
    pml4: &mut PageTable,
    virt: VirtAddr,
    phys: PhysAddr,
    flags: u64,
    allocator: &mut dyn FrameAllocator,
) -> Result<(), MapError> {
    // SAFETY: Caller guarantees pml4 is valid. We walk the table
    // hierarchy, allocating intermediate tables as needed.
    unsafe { ... }
}
```

## Error Handling

- Use `oncrix_lib::Result<T>` (alias for `Result<T, Error>`)
- Propagate errors with `?`
- No `unwrap()` or `expect()` in production code paths
- Define domain-specific error types when the global `Error` enum
  doesn't capture enough context

## Documentation

- All `pub` items must have `///` doc comments
- Module-level docs with `//!` explaining the module's purpose
- Include `# Safety` sections on unsafe functions
- Include `# Panics` sections if a function can panic

## Integer Arithmetic

- Use `checked_*` for untrusted input (syscall args, user data)
- Use `saturating_*` for counters and statistics
- Use `wrapping_*` only when overflow is intentional (e.g., hash)
- Document the choice when it's not obvious

## License Header

Every source file must start with:

```rust
// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0
```

## Inline Assembly

- Use `core::arch::asm!()`, not separate `.S` files
- Gate with `#[cfg(target_arch = "x86_64")]`
- Document register usage and side effects
- Use `options(nomem, nostack, preserves_flags)` where applicable
- Do NOT use `preserves_flags` if the instruction modifies FLAGS
