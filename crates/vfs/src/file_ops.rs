// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Unified file operations layer for fd-backed I/O dispatch.
//!
//! Provides a [`FileOps`] trait that all fd-backed types implement,
//! a [`FileKind`] enum for discriminating between backend types,
//! a [`UnifiedFd`] wrapper combining kind, inode, and flags, and
//! a [`UnifiedFdTable`] mapping fd numbers to [`UnifiedFd`] entries.
//!
//! Top-level dispatch functions ([`fd_read`], [`fd_write`], [`fd_close`],
//! [`fd_dup`]) route operations to the correct backend based on the
//! file descriptor's [`FileKind`].

use crate::file::Fd;
use crate::inode::InodeNumber;
use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of file descriptors per process.
pub const MAX_FDS: usize = 256;

/// O_NONBLOCK flag bit.
pub const O_NONBLOCK: u32 = 0o4000;

/// O_CLOEXEC flag bit.
pub const O_CLOEXEC: u32 = 0o2000000;

// ── Poll readiness flags ─────────────────────────────────────────────

/// Readiness flags returned by [`FileOps::poll_ready`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollFlags(pub u32);

impl PollFlags {
    /// Readable data is available.
    pub const READABLE: Self = Self(0x01);
    /// Writing will not block.
    pub const WRITABLE: Self = Self(0x02);
    /// Error condition.
    pub const ERROR: Self = Self(0x04);
    /// Hang-up (peer closed).
    pub const HANGUP: Self = Self(0x08);
    /// Empty (no events).
    pub const NONE: Self = Self(0);

    /// Test whether `flag` is set.
    pub const fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) != 0
    }

    /// Combine two flag sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl core::fmt::Display for PollFlags {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PollFlags({:#x})", self.0)
    }
}

// ── FileOps trait ────────────────────────────────────────────────────

/// Trait for fd-backed I/O backends.
///
/// Each fd-backed type (pipe, socket, pty, etc.) implements this
/// trait so that the unified dispatch layer can forward read, write,
/// poll, ioctl, and close operations without knowing the concrete
/// type at compile time.
pub trait FileOps {
    /// Read up to `len` bytes into `buf`.
    ///
    /// Returns the number of bytes actually read, or an error.
    /// Backends that do not support reading return
    /// `Err(Error::NotImplemented)`.
    fn read(&mut self, buf: &mut [u8], len: usize) -> Result<usize>;

    /// Write up to `len` bytes from `buf`.
    ///
    /// Returns the number of bytes actually written, or an error.
    /// Backends that do not support writing return
    /// `Err(Error::NotImplemented)`.
    fn write(&mut self, buf: &[u8], len: usize) -> Result<usize>;

    /// Query the current poll-readiness of this file.
    fn poll_ready(&self) -> PollFlags;

    /// Perform a device-specific I/O control operation.
    ///
    /// `request` identifies the operation; `arg` is an opaque
    /// argument whose meaning depends on the request.
    fn ioctl(&mut self, request: u32, arg: usize) -> Result<usize>;

    /// Release resources held by this file description.
    fn close(&mut self) -> Result<()>;
}

// ── FileKind ─────────────────────────────────────────────────────────

/// Discriminant for fd-backed I/O types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// Regular file backed by a filesystem inode.
    Regular,
    /// Pipe (unidirectional byte stream).
    Pipe,
    /// Network or Unix-domain socket.
    Socket,
    /// Pseudo-terminal (master or slave side).
    Pty,
    /// eventfd — inter-process event notification.
    EventFd,
    /// signalfd — synchronous signal delivery.
    SignalFd,
    /// timerfd — timer expiration notification.
    TimerFd,
    /// epoll — I/O event notification facility.
    Epoll,
    /// inotify — filesystem event monitor.
    Inotify,
}

impl core::fmt::Display for FileKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Regular => write!(f, "regular"),
            Self::Pipe => write!(f, "pipe"),
            Self::Socket => write!(f, "socket"),
            Self::Pty => write!(f, "pty"),
            Self::EventFd => write!(f, "eventfd"),
            Self::SignalFd => write!(f, "signalfd"),
            Self::TimerFd => write!(f, "timerfd"),
            Self::Epoll => write!(f, "epoll"),
            Self::Inotify => write!(f, "inotify"),
        }
    }
}

// ── FdFlags ──────────────────────────────────────────────────────────

/// Per-fd status flags (O_NONBLOCK, O_CLOEXEC, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdFlags(pub u32);

impl FdFlags {
    /// No flags set.
    pub const EMPTY: Self = Self(0);

    /// Test whether the O_NONBLOCK bit is set.
    pub const fn is_nonblock(self) -> bool {
        (self.0 & O_NONBLOCK) != 0
    }

    /// Test whether the O_CLOEXEC bit is set.
    pub const fn is_cloexec(self) -> bool {
        (self.0 & O_CLOEXEC) != 0
    }

    /// Return flags with O_CLOEXEC cleared (used by dup).
    pub const fn without_cloexec(self) -> Self {
        Self(self.0 & !O_CLOEXEC)
    }
}

impl core::fmt::Display for FdFlags {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "FdFlags({:#x})", self.0)
    }
}

// ── UnifiedFd ────────────────────────────────────────────────────────

/// A unified file descriptor entry combining the backend kind,
/// an optional inode reference, and per-fd flags.
#[derive(Debug, Clone, Copy)]
pub struct UnifiedFd {
    /// Backend type that handles I/O for this fd.
    pub kind: FileKind,
    /// Inode number (meaningful for regular files; may be zero for
    /// anonymous objects like pipes or eventfds).
    pub inode: InodeNumber,
    /// Per-fd status flags.
    pub flags: FdFlags,
}

impl UnifiedFd {
    /// Create a new unified fd entry.
    pub const fn new(kind: FileKind, inode: InodeNumber, flags: FdFlags) -> Self {
        Self { kind, inode, flags }
    }
}

impl core::fmt::Display for UnifiedFd {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "UnifiedFd({}, {}, {})",
            self.kind, self.inode, self.flags
        )
    }
}

// ── UnifiedFdTable ───────────────────────────────────────────────────

/// Per-process table mapping fd numbers to [`UnifiedFd`] entries.
///
/// Supports up to [`MAX_FDS`] (256) open file descriptors per
/// process, matching POSIX OPEN_MAX.
pub struct UnifiedFdTable {
    /// Fixed-size slot array.
    slots: [Option<UnifiedFd>; MAX_FDS],
}

impl core::fmt::Debug for UnifiedFdTable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let open = self.slots.iter().filter(|s| s.is_some()).count();
        f.debug_struct("UnifiedFdTable")
            .field("open_count", &open)
            .finish()
    }
}

impl Default for UnifiedFdTable {
    fn default() -> Self {
        Self::new()
    }
}

impl UnifiedFdTable {
    /// Create an empty fd table.
    pub const fn new() -> Self {
        const NONE: Option<UnifiedFd> = None;
        Self {
            slots: [NONE; MAX_FDS],
        }
    }

    /// Allocate the lowest available fd for the given entry.
    pub fn alloc(&mut self, entry: UnifiedFd) -> Result<Fd> {
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(entry);
                return Ok(Fd(i as u32));
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Get an entry by fd number.
    pub fn get(&self, fd: Fd) -> Option<&UnifiedFd> {
        self.slots.get(fd.0 as usize).and_then(|s| s.as_ref())
    }

    /// Get a mutable entry by fd number.
    pub fn get_mut(&mut self, fd: Fd) -> Option<&mut UnifiedFd> {
        self.slots.get_mut(fd.0 as usize).and_then(|s| s.as_mut())
    }

    /// Close an fd slot, returning the entry that was removed.
    pub fn remove(&mut self, fd: Fd) -> Result<UnifiedFd> {
        let slot = self
            .slots
            .get_mut(fd.0 as usize)
            .ok_or(Error::InvalidArgument)?;
        slot.take().ok_or(Error::InvalidArgument)
    }

    /// Insert an entry at a specific fd number, replacing any
    /// existing entry. Returns the old entry if one was present.
    pub fn insert_at(&mut self, fd: Fd, entry: UnifiedFd) -> Result<Option<UnifiedFd>> {
        let slot = self
            .slots
            .get_mut(fd.0 as usize)
            .ok_or(Error::InvalidArgument)?;
        let old = slot.take();
        *slot = Some(entry);
        Ok(old)
    }

    /// Return the number of currently open fds.
    pub fn open_count(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }
}

// ── Top-level dispatch functions ─────────────────────────────────────

/// Read up to `len` bytes from the file descriptor `fd`.
///
/// Dispatches to the appropriate backend based on the fd's
/// [`FileKind`]. For types that have not yet been wired to a
/// concrete backend, returns `Err(Error::NotImplemented)`.
///
/// # Errors
///
/// - `InvalidArgument` if `fd` is not a valid open descriptor.
/// - `NotImplemented` if the backend type has no read support yet.
/// - Backend-specific errors propagated from the concrete read
///   implementation.
pub fn fd_read(table: &UnifiedFdTable, fd: Fd, _buf: &mut [u8], _len: usize) -> Result<usize> {
    let entry = table.get(fd).ok_or(Error::InvalidArgument)?;

    match entry.kind {
        FileKind::Regular
        | FileKind::Pipe
        | FileKind::Socket
        | FileKind::Pty
        | FileKind::EventFd
        | FileKind::SignalFd
        | FileKind::TimerFd => {
            // Concrete backend dispatch will be wired here once
            // each subsystem exposes a FileOps implementation.
            Err(Error::NotImplemented)
        }
        FileKind::Epoll | FileKind::Inotify => {
            // epoll and inotify fds are not directly readable via
            // the read(2) path.
            Err(Error::InvalidArgument)
        }
    }
}

/// Write up to `len` bytes to the file descriptor `fd`.
///
/// Dispatches to the appropriate backend based on the fd's
/// [`FileKind`]. For types that have not yet been wired to a
/// concrete backend, returns `Err(Error::NotImplemented)`.
///
/// # Errors
///
/// - `InvalidArgument` if `fd` is not a valid open descriptor.
/// - `NotImplemented` if the backend type has no write support yet.
/// - Backend-specific errors propagated from the concrete write
///   implementation.
pub fn fd_write(table: &UnifiedFdTable, fd: Fd, _buf: &[u8], _len: usize) -> Result<usize> {
    let entry = table.get(fd).ok_or(Error::InvalidArgument)?;

    match entry.kind {
        FileKind::Regular
        | FileKind::Pipe
        | FileKind::Socket
        | FileKind::Pty
        | FileKind::EventFd => {
            // Concrete backend dispatch will be wired here once
            // each subsystem exposes a FileOps implementation.
            Err(Error::NotImplemented)
        }
        FileKind::SignalFd | FileKind::TimerFd | FileKind::Epoll | FileKind::Inotify => {
            // These fd types do not support write(2).
            Err(Error::InvalidArgument)
        }
    }
}

/// Close the file descriptor `fd`, releasing its table slot and
/// invoking the backend's close logic.
///
/// # Errors
///
/// - `InvalidArgument` if `fd` is not a valid open descriptor.
pub fn fd_close(table: &mut UnifiedFdTable, fd: Fd) -> Result<()> {
    let _entry = table.remove(fd)?;

    // Backend-specific cleanup (e.g., decrementing pipe refcounts,
    // removing epoll watches) will be dispatched here once each
    // subsystem exposes a FileOps::close implementation.
    Ok(())
}

/// Duplicate `old_fd` to `new_fd` with dup2 semantics.
///
/// If `new_fd` already refers to an open file, it is silently
/// closed first. The duplicated fd inherits the same [`FileKind`]
/// and inode but has O_CLOEXEC cleared (POSIX dup2 behaviour).
///
/// If `old_fd == new_fd` and `old_fd` is valid, the call succeeds
/// without closing and returns `new_fd` unchanged.
///
/// # Errors
///
/// - `InvalidArgument` if `old_fd` is not a valid open descriptor
///   or `new_fd` is out of range.
pub fn fd_dup(table: &mut UnifiedFdTable, old_fd: Fd, new_fd: Fd) -> Result<usize> {
    // Validate old_fd.
    let source = *table.get(old_fd).ok_or(Error::InvalidArgument)?;

    // Validate new_fd range.
    if new_fd.0 as usize >= MAX_FDS {
        return Err(Error::InvalidArgument);
    }

    // dup2: if old_fd == new_fd, return immediately.
    if old_fd == new_fd {
        return Ok(new_fd.0 as usize);
    }

    // Build the duplicated entry with O_CLOEXEC cleared.
    let dup_entry = UnifiedFd::new(source.kind, source.inode, source.flags.without_cloexec());

    // If new_fd was open, the insert_at replaces it (implicit close).
    let _old = table.insert_at(new_fd, dup_entry)?;

    Ok(new_fd.0 as usize)
}
