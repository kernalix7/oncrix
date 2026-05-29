// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-thread file descriptor table — data types only.
//!
//! This module holds the plain-data types ([`FileBackend`], [`FileHandle`],
//! [`KernelFdTable`]) that are embedded directly in [`crate::thread::Thread`]
//! so that each thread owns its fd table independently.
//!
//! I/O dispatch (read, write, lseek) and the syscall-level helpers
//! (`fd_install`, `fd_get`, `fd_close`, `fd_dup2`) remain in
//! `oncrix_kernel::fd_table` where they can call into VFS, pipe, and
//! socket subsystems without creating circular crate dependencies.
//!
//! # POSIX.1-2024 references
//!
//! - `open(3p)` — fd allocation, lowest-available rule.
//! - `close(3p)` — fd de-allocation.
//! - `fork(3p)` — "the child inherits copies of the parent's set of open
//!   file descriptors" (each fd is duplicated, not shared).

use oncrix_lib::{Error, Result};
use oncrix_vfs::inode::InodeNumber;

// ── Constants ─────────────────────────────────────────────────────

/// Maximum number of open file descriptors per process (POSIX OPEN_MAX).
pub const MAX_FDS: usize = 32;

// ── DevFileKind ───────────────────────────────────────────────────

/// Selects which synthetic device a [`FileBackend::DevFile`] handle targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevFileKind {
    /// `/dev/null`: reads return EOF (0 bytes); writes silently succeed.
    Null,
    /// `/dev/zero`: reads return all-zero bytes; writes silently succeed.
    Zero,
}

// ── ProcFileKind ──────────────────────────────────────────────────

/// Selects which synthetic `/proc` file a [`FileBackend::ProcFile`] handle targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProcFileKind {
    /// `/proc/uptime`
    Uptime = 0,
    /// `/proc/version`
    Version = 1,
    /// `/proc/meminfo`
    Meminfo = 2,
}

// ── FileBackend ───────────────────────────────────────────────────

/// The backing resource for an open file description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileBackend {
    /// The kernel console — backed by COM1 serial output.
    Console,

    /// A regular file (or directory) in the ramfs.
    RamfsFile {
        /// Inode number in the global ramfs.
        ino: InodeNumber,
    },

    /// One end of an anonymous pipe.
    Pipe {
        /// Index into the global pipe ring table.
        ring_id: u32,
        /// `true` for the write end; `false` for the read end.
        is_write_end: bool,
    },

    /// A Unix-domain socket handle.
    Socket {
        /// Index into the global socket registry.
        handle_id: u32,
    },

    /// One end of a `socketpair(2)` AF_UNIX/SOCK_STREAM connection,
    /// backed by two pipe rings: this end reads from `read_ring` and
    /// writes to `write_ring` (the peer's rings are swapped).
    SocketPair {
        /// Pipe ring this end reads from.
        read_ring: u32,
        /// Pipe ring this end writes to.
        write_ring: u32,
    },

    /// A synthetic device file (`/dev/null` or `/dev/zero`).
    DevFile {
        /// Which synthetic device this handle targets.
        kind: DevFileKind,
    },

    /// A synthetic procfs file (`/proc/uptime`, `/proc/version`, etc.).
    ProcFile {
        /// Which `/proc` entry this handle targets.
        kind: ProcFileKind,
    },

    /// An `eventfd(2)` counter object.
    EventFd {
        /// Index into the global eventfd registry.
        id: u32,
    },

    /// An `epoll(7)` instance.
    EpollInstance {
        /// Index into the global epoll registry.
        id: u32,
    },

    /// A `timerfd(2)` timer object.
    TimerFd {
        /// Index into the global timerfd registry.
        id: u32,
    },

    /// A `signalfd(2)` signal-pending file descriptor.
    SignalFd {
        /// Index into the global signalfd registry.
        id: u32,
    },
}

// ── HandleFlags ───────────────────────────────────────────────────

/// Per-fd status flags stored alongside each open file description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandleFlags(pub u32);

impl HandleFlags {
    /// No flags.
    pub const RDONLY: Self = Self(0);
    /// Write-only.
    pub const WRONLY: Self = Self(1);
    /// Read-write.
    pub const RDWR: Self = Self(2);
    /// Append mode: writes always go to EOF.
    pub const APPEND: Self = Self(0o2000);

    /// Non-blocking mode (`O_NONBLOCK`).
    pub const NONBLOCK: u32 = 0o4000;

    /// File-status flag bits settable via `fcntl(F_SETFL)`.
    ///
    /// POSIX restricts `F_SETFL` to the file-status flags; the access mode
    /// and creation flags in `arg` are ignored. We honour `O_APPEND` and
    /// `O_NONBLOCK`.
    pub const SETFL_MASK: u32 = 0o2000 | 0o4000;

    /// `FD_CLOEXEC` descriptor flag, stored in a reserved high bit so it
    /// never collides with `O_*` open-flag bits. Manipulated only via
    /// `fcntl(F_GETFD/F_SETFD)`.
    pub const FD_CLOEXEC_BIT: u32 = 0x8000_0000;

    /// Return `true` if writing is allowed (O_WRONLY or O_RDWR).
    pub const fn is_writable(self) -> bool {
        (self.0 & 0b11) != 0
    }

    /// Return `true` if reading is allowed (not O_WRONLY).
    pub const fn is_readable(self) -> bool {
        (self.0 & 0b11) != 1
    }

    /// Return `true` if O_APPEND is set.
    pub const fn is_append(self) -> bool {
        (self.0 & 0o2000) != 0
    }

    /// Return `true` if O_NONBLOCK is set.
    pub const fn is_nonblock(self) -> bool {
        (self.0 & Self::NONBLOCK) != 0
    }

    /// Return `true` if the `FD_CLOEXEC` descriptor flag is set.
    pub const fn is_cloexec(self) -> bool {
        (self.0 & Self::FD_CLOEXEC_BIT) != 0
    }

    /// Return the open flags with the reserved `FD_CLOEXEC` bit masked off
    /// (the value `fcntl(F_GETFL)` should report).
    pub const fn open_flags(self) -> u32 {
        self.0 & !Self::FD_CLOEXEC_BIT
    }
}

// ── FileHandle ────────────────────────────────────────────────────

/// An open file description.
///
/// Tracks the backing resource, current byte offset, and open flags.
#[derive(Debug, Clone, Copy)]
pub struct FileHandle {
    /// What backs this file description.
    pub backend: FileBackend,
    /// Current seek offset (bytes from file start).
    pub offset: u64,
    /// Open mode flags.
    pub flags: HandleFlags,
}

impl FileHandle {
    /// Create a console handle (used for fd 0, 1, 2).
    pub const fn console() -> Self {
        Self {
            backend: FileBackend::Console,
            offset: 0,
            flags: HandleFlags::RDWR,
        }
    }

    /// Create a ramfs file handle.
    pub const fn ramfs_file(ino: InodeNumber, flags: HandleFlags) -> Self {
        Self {
            backend: FileBackend::RamfsFile { ino },
            offset: 0,
            flags,
        }
    }

    /// Create a synthetic device file handle.
    pub const fn dev_file(kind: DevFileKind, flags: HandleFlags) -> Self {
        Self {
            backend: FileBackend::DevFile { kind },
            offset: 0,
            flags,
        }
    }

    /// Create a synthetic procfs file handle.
    pub const fn proc_file(kind: ProcFileKind, flags: HandleFlags) -> Self {
        Self {
            backend: FileBackend::ProcFile { kind },
            offset: 0,
            flags,
        }
    }
}

// ── KernelFdTable ─────────────────────────────────────────────────

/// Per-thread file descriptor table.
///
/// Fixed-size array of [`MAX_FDS`] slots. Slot index == fd number.
/// The lowest free slot is allocated on each `install` call
/// (POSIX lowest-available-fd rule).
#[derive(Debug)]
pub struct KernelFdTable {
    /// Open file description slots.
    slots: [Option<FileHandle>; MAX_FDS],
}

impl KernelFdTable {
    /// Create an empty fd table.
    pub const fn new() -> Self {
        const NONE: Option<FileHandle> = None;
        Self {
            slots: [NONE; MAX_FDS],
        }
    }

    /// Install standard I/O file descriptors (0=stdin, 1=stdout, 2=stderr)
    /// all pointing at the console backend.
    pub fn install_stdio(&mut self) {
        self.slots[0] = Some(FileHandle::console());
        self.slots[1] = Some(FileHandle::console());
        self.slots[2] = Some(FileHandle::console());
    }

    /// Allocate the lowest available fd for `handle`.
    pub fn install(&mut self, handle: FileHandle) -> Result<usize> {
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(handle);
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory) // EMFILE
    }

    /// Allocate the lowest available fd `>= min_fd` for `handle`.
    ///
    /// Backs `fcntl(F_DUPFD)`, which requires the new descriptor be the
    /// lowest free one at or above the caller-supplied floor. Returns
    /// `Err(InvalidArgument)` if `min_fd` is out of range, `OutOfMemory`
    /// (EMFILE) if no slot at or above `min_fd` is free.
    pub fn install_from(&mut self, min_fd: usize, handle: FileHandle) -> Result<usize> {
        if min_fd >= MAX_FDS {
            return Err(Error::InvalidArgument);
        }
        for (i, slot) in self.slots.iter_mut().enumerate().skip(min_fd) {
            if slot.is_none() {
                *slot = Some(handle);
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory) // EMFILE
    }

    /// Install `handle` at the explicit slot `fd`, overwriting any existing entry.
    pub fn install_at(&mut self, fd: usize, handle: FileHandle) -> Result<()> {
        let slot = self.slots.get_mut(fd).ok_or(Error::InvalidArgument)?;
        *slot = Some(handle);
        Ok(())
    }

    /// Return a copy of the handle at `fd`.
    pub fn get(&self, fd: usize) -> Option<FileHandle> {
        self.slots.get(fd).and_then(|s| *s)
    }

    /// Return a mutable reference to the handle at `fd`.
    pub fn get_mut(&mut self, fd: usize) -> Option<&mut FileHandle> {
        self.slots.get_mut(fd).and_then(|s| s.as_mut())
    }

    /// Close fd `fd`, releasing its slot.
    ///
    /// Returns `Err(InvalidArgument)` (EBADF) if the fd is not open.
    pub fn close(&mut self, fd: usize) -> Result<FileHandle> {
        let slot = self.slots.get_mut(fd).ok_or(Error::InvalidArgument)?;
        slot.take().ok_or(Error::InvalidArgument)
    }

    /// Return an iterator over all occupied slots: `(fd_number, &FileHandle)`.
    pub fn iter(&self) -> impl Iterator<Item = (usize, &FileHandle)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|h| (i, h)))
    }
}

impl Default for KernelFdTable {
    fn default() -> Self {
        Self::new()
    }
}
