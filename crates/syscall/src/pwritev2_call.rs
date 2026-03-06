// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `pwritev2(2)` syscall handler — write data from scattered buffers with flags.
//!
//! `pwritev2` extends `pwritev` with per-call `flags`.  It writes data from
//! `iovcnt` scatter buffers described by `iov` to file descriptor `fd` at
//! position `offset`.  A negative `offset` writes at the file's current
//! position (like `writev`).
//!
//! # Syscall signature
//!
//! ```text
//! ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt,
//!                  off_t offset, int flags);
//! ```
//!
//! # Flags
//!
//! | Flag | Value | Description |
//! |------|-------|-------------|
//! | `RWF_HIPRI`  | 0x01 | High-priority I/O |
//! | `RWF_DSYNC`  | 0x02 | Per-I/O `O_DSYNC` |
//! | `RWF_SYNC`   | 0x04 | Per-I/O `O_SYNC` |
//! | `RWF_NOWAIT` | 0x08 | Non-blocking write |
//! | `RWF_APPEND` | 0x10 | Append regardless of offset |
//!
//! # References
//!
//! - Linux: `fs/read_write.c`
//! - `pwritev2(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// High-priority I/O hint.
pub const RWF_HIPRI: i32 = 0x01;
/// Per-I/O data-sync.
pub const RWF_DSYNC: i32 = 0x02;
/// Per-I/O full sync.
pub const RWF_SYNC: i32 = 0x04;
/// Non-blocking I/O.
pub const RWF_NOWAIT: i32 = 0x08;
/// Append to end of file.
pub const RWF_APPEND: i32 = 0x10;

/// Maximum number of iovec elements.
pub const UIO_MAXIOV: i32 = 1024;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// A single gather buffer descriptor.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct IoVec {
    /// User-space buffer pointer.
    pub iov_base: u64,
    /// Length of the buffer in bytes.
    pub iov_len: u64,
}

impl IoVec {
    /// Create a new iovec element.
    pub const fn new(iov_base: u64, iov_len: u64) -> Self {
        Self { iov_base, iov_len }
    }
}

/// Parameters for a `pwritev2` call.
#[derive(Debug, Clone, Copy)]
pub struct Pwritev2Request {
    /// Open file descriptor to write to.
    pub fd: i32,
    /// User-space pointer to the iovec array.
    pub iov: u64,
    /// Number of iovec elements.
    pub iovcnt: i32,
    /// File offset (`-1` = use current position).
    pub offset: i64,
    /// I/O flags (`RWF_*`).
    pub flags: i32,
}

impl Pwritev2Request {
    /// Create a new request.
    pub const fn new(fd: i32, iov: u64, iovcnt: i32, offset: i64, flags: i32) -> Self {
        Self {
            fd,
            iov,
            iovcnt,
            offset,
            flags,
        }
    }

    /// Validate the request.
    pub fn validate(&self) -> Result<()> {
        if self.fd < 0 {
            return Err(Error::InvalidArgument);
        }
        if self.iovcnt <= 0 || self.iovcnt > UIO_MAXIOV {
            return Err(Error::InvalidArgument);
        }
        if self.iov == 0 {
            return Err(Error::InvalidArgument);
        }
        let known = RWF_HIPRI | RWF_DSYNC | RWF_SYNC | RWF_NOWAIT | RWF_APPEND;
        if self.flags & !known != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Return whether append mode is requested.
    pub fn is_append(&self) -> bool {
        self.flags & RWF_APPEND != 0
    }

    /// Return whether sync-on-write is requested.
    pub fn is_sync(&self) -> bool {
        self.flags & RWF_SYNC != 0
    }
}

impl Default for Pwritev2Request {
    fn default() -> Self {
        Self::new(0, 0, 0, -1, 0)
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle the `pwritev2(2)` syscall.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — negative fd, zero/excess iovcnt, null iov,
///   or unknown flags.
/// - [`Error::WouldBlock`] — non-blocking mode and buffer is full.
/// - [`Error::NotImplemented`] — VFS write path not yet wired.
pub fn sys_pwritev2(fd: i32, iov: u64, iovcnt: i32, offset: i64, flags: i32) -> Result<i64> {
    let req = Pwritev2Request::new(fd, iov, iovcnt, offset, flags);
    req.validate()?;
    do_pwritev2(&req)
}

fn do_pwritev2(req: &Pwritev2Request) -> Result<i64> {
    let _ = req;
    // TODO: Gather iov array from user space, dispatch to the file's write_iter
    // operation with the specified offset and flags.
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_pwritev2_syscall(fd: i32, iov: u64, iovcnt: i32, offset: i64, flags: i32) -> Result<i64> {
    sys_pwritev2(fd, iov, iovcnt, offset, flags)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_fd_rejected() {
        assert_eq!(
            sys_pwritev2(-1, 1, 1, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn zero_iovcnt_rejected() {
        assert_eq!(
            sys_pwritev2(0, 1, 0, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn too_many_iov_rejected() {
        assert_eq!(
            sys_pwritev2(0, 1, UIO_MAXIOV + 1, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_iov_rejected() {
        assert_eq!(
            sys_pwritev2(0, 0, 1, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(
            sys_pwritev2(0, 1, 1, 0, 0x100).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn append_flag_detected() {
        let req = Pwritev2Request::new(0, 1, 1, 0, RWF_APPEND);
        assert!(req.is_append());
    }

    #[test]
    fn sync_flag_detected() {
        let req = Pwritev2Request::new(0, 1, 1, 0, RWF_SYNC);
        assert!(req.is_sync());
    }
}
