# User-Space Access Validation

## Overview

Before the kernel dereferences any pointer from user space, it must
validate that the pointer falls within the user-space address range
and is properly aligned. The `uaccess` module provides safe abstractions.

## Functions

### `validate_user_range(ptr, len)`

Checks that `[ptr, ptr+len)` is entirely within user space.

```rust
pub fn validate_user_range(ptr: u64, len: u64) -> Result<()>;
```

Returns `InvalidArgument` if:
- `ptr < USER_SPACE_START`
- `ptr + len` wraps around (overflow)
- `ptr + len > USER_SPACE_END + 1`

### `validate_user_string(ptr, max_len)`

Walks memory looking for a null terminator. Returns the string
length (not including null byte).

**Safety**: Caller must ensure the memory at `ptr` is actually mapped.

### `copy_from_user(dst, src, len)`

Copies `len` bytes from user-space address `src` to kernel buffer `dst`.

### `copy_to_user(dst, src, len)`

Copies `len` bytes from kernel buffer `src` to user-space address `dst`.

### `get_user_u64(addr)` / `put_user_u64(addr, value)`

Read/write a single `u64` at a user-space address. Requires 8-byte
alignment.

## Security Note

These functions only validate the **address range**, not the
**page table mappings**. The caller must ensure pages are actually
mapped (or handle page faults). In the future, ONCRIX will use
a fault-on-copy model similar to Linux's.

## Usage Pattern

```rust
// In a syscall handler:
pub fn sys_read(fd: u64, buf: u64, count: u64) -> SyscallResult {
    // 1. Validate the user buffer
    if let Err(e) = validate_user_range(buf, count) {
        return error_to_errno(e);
    }
    // 2. Read data from VFS
    let data = vfs_read(fd, count)?;
    // 3. Copy to user space
    unsafe { copy_to_user(buf, &data, data.len())? };
    data.len() as SyscallResult
}
```
