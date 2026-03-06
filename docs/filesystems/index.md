# File Systems

ONCRIX implements a virtual file system (VFS) layer that abstracts
multiple filesystem implementations behind a uniform interface.

## Contents

- [VFS Architecture](vfs.md) — Inodes, dentries, superblocks
- [ramfs](ramfs.md) — In-memory filesystem
- [devfs](devfs.md) — Device node filesystem
- [procfs](procfs.md) — Process information filesystem
- [Pipes](pipes.md) — POSIX pipe implementation
- [Path Resolution](path-resolution.md) — How paths are resolved

---

## Overview

### Microkernel Filesystem Strategy

In the ONCRIX microkernel, the VFS layer provides minimal in-kernel
abstractions. Actual filesystem servers run in user space:

```
┌──────────────────────────────────┐
│          User Space              │
│  ┌─────────┐  ┌───────────────┐ │
│  │ ext2    │  │ oncrix-fs     │ │
│  │ server  │  │ server        │ │
│  └────┬────┘  └──────┬────────┘ │
│       │              │          │
│  ─ ─ ─│─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─  │
│       ▼              ▼          │
│  ┌──────────────────────────────┐
│  │     VFS (kernel-side)        │
│  │  inode → dentry → mount     │
│  └──────────────────────────────┘
│            Kernel                │
└──────────────────────────────────┘
```

### Currently Implemented

| Filesystem | Type | Description |
|------------|------|-------------|
| ramfs | In-memory | 128 inodes, 4 KiB files |
| devfs | Virtual | Character/block device nodes |
| procfs | Virtual | `/proc` — version, uptime, meminfo |

### Inode Model

Every file, directory, and device is represented by an `Inode`:

```rust
pub struct InodeNumber(u64);

pub enum FileType {
    Regular,
    Directory,
    CharDevice,
    BlockDevice,
    Pipe,
    Symlink,
}

pub trait InodeOps {
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<usize>;
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<usize>;
    fn lookup(&self, name: &str) -> Result<InodeNumber>;
    fn create(&mut self, name: &str, file_type: FileType) -> Result<InodeNumber>;
    // ... etc
}
```

### POSIX Compatibility

| Operation | Syscall | Status |
|-----------|---------|--------|
| Open | `open(2)` | Implemented |
| Read | `read(2)` | VFS connected |
| Write | `write(2)` | VFS connected |
| Close | `close(2)` | Stub |
| Stat | `stat(2)` | Stub |
| Lseek | `lseek(2)` | VFS connected |
| Pipe | `pipe(2)` | Ring buffer |
| Dup2 | `dup2(2)` | Stub |
| Mkdir | `mkdir(2)` | ramfs |
| Rmdir | `rmdir(2)` | ramfs |
| Unlink | `unlink(2)` | ramfs |
