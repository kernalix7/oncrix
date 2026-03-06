# Core API

Internal kernel API reference for ONCRIX subsystems.

## Contents

- [Error Handling](errors.md) — `Error` enum, `Result` type, errno mapping
- [System Calls](syscalls.md) — POSIX syscall ABI and handler list
- [User Access](uaccess.md) — Safe user-space pointer validation
- [ELF Loading](elf.md) — ELF64 binary parsing and loading
- [Glossary](glossary.md) — ONCRIX-specific terminology

---

## Error Type

All fallible operations use `oncrix_lib::Result<T>`:

```rust
pub type Result<T> = core::result::Result<T, Error>;

pub enum Error {
    PermissionDenied,   // EACCES (13)
    NotFound,           // ENOENT (2)
    OutOfMemory,        // ENOMEM (12)
    InvalidArgument,    // EINVAL (22)
    Busy,               // EBUSY (16)
    WouldBlock,         // EAGAIN (11)
    Interrupted,        // EINTR (4)
    IoError,            // EIO (5)
    NotImplemented,     // ENOSYS (38)
    AlreadyExists,      // EEXIST (17)
}
```

## Crate Dependencies

```
oncrix-lib          ← Foundation (Error, Result)
  ↑
oncrix-mm           ← Memory management
  ↑
oncrix-hal          ← Hardware abstraction
  ↑
oncrix-ipc          ← IPC primitives
  ↑
oncrix-process      ← Process/thread management
  ↑
oncrix-vfs          ← Virtual filesystem
  ↑
oncrix-drivers      ← Device drivers
  ↑
oncrix-syscall      ← System call interface
  ↑
oncrix-kernel       ← Kernel core (ties everything together)
  ↑
oncrix-bootloader   ← Boot protocol
```
