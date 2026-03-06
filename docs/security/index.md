# Security Architecture

## Overview

ONCRIX's security model is built on three pillars:

1. **Microkernel isolation** — Services run in separate address spaces
2. **Capability-based access control** — No ambient authority
3. **Rust memory safety** — No buffer overflows, use-after-free, or data races

## Privilege Separation

```
Ring 0 (Kernel)
┌─────────────────────────────┐
│  Scheduler  │  IPC  │  MM   │  ← Minimal TCB
└─────────────────────────────┘

Ring 3 (User Space)
┌──────────┐ ┌──────────┐ ┌──────────┐
│  Driver   │ │   VFS    │ │ Network  │
│  Server   │ │  Server  │ │  Stack   │
└──────────┘ └──────────┘ └──────────┘
```

Only scheduling, IPC, and memory management run in Ring 0. Everything
else (drivers, filesystems, network) runs as user-space processes
with minimal privileges.

## Capability Model

(Planned — not yet implemented)

A capability is an unforgeable token that grants specific access:

```rust
pub struct Capability {
    object_id: u64,
    rights: CapRights,
}

pub struct CapRights {
    read: bool,
    write: bool,
    execute: bool,
    grant: bool,   // Can delegate to others
}
```

Rules:
- A process can only access resources it has capabilities for
- Capabilities can be delegated via IPC (with optional right reduction)
- The kernel enforces capability checks on every operation
- No global namespace — processes can't discover resources by name

## User Pointer Validation

All syscall handlers validate user-space pointers before dereferencing:

1. Range check: `[ptr, ptr+len)` within `USER_SPACE_START..USER_SPACE_END`
2. Overflow check: `ptr + len` does not wrap around
3. Alignment check: for typed access (e.g., `u64` requires 8-byte align)

See [User Access](../core-api/uaccess.md) for details.

## Signal Security

- `SIGKILL` and `SIGSTOP` cannot be caught, blocked, or ignored
- Signal handlers are reset to `SIG_DFL` on `execve`
- Only the process owner (or root equivalent) can send signals

## Memory Safety

| Threat | ONCRIX Mitigation |
|--------|------------------|
| Buffer overflow | Rust bounds checking |
| Use-after-free | Rust ownership model |
| NULL deref | `Option<T>` instead of null pointers |
| Data races | Borrow checker, `Send`/`Sync` traits |
| Integer overflow | `checked_*`/`saturating_*` arithmetic |
| Stack overflow | Guard pages (planned) |
| Code injection | W^X (writable xor executable pages) |
| Kernel exploit | Minimal TCB in Ring 0 |

## Threat Model

### In Scope

- Malicious user-space processes
- Buggy device drivers (isolated in user space)
- Filesystem corruption (handled by FS server, not kernel)

### Out of Scope (for now)

- Physical access attacks
- Side-channel attacks (Spectre, Meltdown)
- Supply chain attacks
- DMA attacks (requires IOMMU — future work)
