# Error Handling

## Error Type

All fallible operations in ONCRIX return `oncrix_lib::Result<T>`:

```rust
pub type Result<T> = core::result::Result<T, Error>;
```

## Error Variants

| Variant | errno | Value | Description |
|---------|-------|-------|-------------|
| `PermissionDenied` | `EACCES` | -13 | Operation not permitted |
| `NotFound` | `ENOENT` | -2 | Resource not found |
| `OutOfMemory` | `ENOMEM` | -12 | No memory available |
| `InvalidArgument` | `EINVAL` | -22 | Invalid argument |
| `Busy` | `EBUSY` | -16 | Resource busy or locked |
| `WouldBlock` | `EAGAIN` | -11 | Operation would block |
| `Interrupted` | `EINTR` | -4 | Operation interrupted |
| `IoError` | `EIO` | -5 | I/O error |
| `NotImplemented` | `ENOSYS` | -38 | Not implemented |
| `AlreadyExists` | `EEXIST` | -17 | Resource already exists |

## Conversion to errno

Syscall handlers use `error_to_errno()` to convert `Error` to
negative errno values returned to user space:

```rust
pub fn error_to_errno(err: Error) -> SyscallResult {
    match err {
        Error::NotFound => -2,          // ENOENT
        Error::PermissionDenied => -13, // EACCES
        Error::OutOfMemory => -12,      // ENOMEM
        // ... etc
    }
}
```

## Best Practices

1. **Propagate with `?`** — Don't match errors unless you need to
   add context or handle a specific case
2. **No `unwrap()`/`expect()`** — Use `?` or `.ok_or(Error::...)?`
3. **Domain-specific errors** — Use when the global `Error` enum
   doesn't capture enough context (e.g., `MapError` for page table)
4. **Display + Debug** — All error types must implement both traits
