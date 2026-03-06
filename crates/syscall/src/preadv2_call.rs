// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `preadv2(2)` syscall handler — read data into scattered buffers with flags.
//!
//! `preadv2` extends `preadv` with additional per-call `flags` that control
//! I/O behaviour.  It reads from file descriptor `fd` at position `offset`
//! into `iovcnt` scatter buffers described by `iov`.  A negative `offset`
//! uses the file's current position (like `readv`).
//!
//! # Syscall signature
//!
//! ```text
//! ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt,
//!                 off_t offset, int flags);
//! ```
//!
//! # Flags
//!
//! | Flag | Value | Description |
//! |------|-------|-------------|
//! | `RWF_HIPRI`    | 0x01 | High-priority I/O |
//! | `RWF_DSYNC`    | 0x02 | Per-I/O `O_DSYNC` |
//! | `RWF_SYNC`     | 0x04 | Per-I/O `O_SYNC` |
//! | `RWF_NOWAIT`   | 0x08 | Do not wait for data not immediately available |
//! | `RWF_APPEND`   | 0x10 | Append to file regardless of offset |
//!
//! # References
//!
//! - Linux: `fs/read_write.c`
//! - `preadv2(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// High-priority I/O hint.
pub const RWF_HIPRI: i32 = 0x01;
/// Per-I/O data-sync (equivalent to `O_DSYNC`).
pub const RWF_DSYNC: i32 = 0x02;
/// Per-I/O sync (equivalent to `O_SYNC`).
pub const RWF_SYNC: i32 = 0x04;
/// Non-blocking I/O — return `EAGAIN` if data is not immediately available.
pub const RWF_NOWAIT: i32 = 0x08;
/// Append data to the end of the file regardless of `offset`.
pub const RWF_APPEND: i32 = 0x10;

/// Maximum number of iovec elements allowed.
pub const UIO_MAXIOV: i32 = 1024;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// A single scatter/gather buffer descriptor.
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

/// Parameters for a `preadv2` call.
#[derive(Debug, Clone, Copy)]
pub struct Preadv2Request {
    /// Open file descriptor to read from.
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

impl Preadv2Request {
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

    /// Validate the request fields.
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

    /// Return whether non-blocking mode is requested.
    pub fn is_nowait(&self) -> bool {
        self.flags & RWF_NOWAIT != 0
    }

    /// Return whether current-position mode is requested.
    pub fn use_current_pos(&self) -> bool {
        self.offset < 0
    }
}

impl Default for Preadv2Request {
    fn default() -> Self {
        Self::new(0, 0, 0, -1, 0)
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle the `preadv2(2)` syscall.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — negative fd, zero/excess iovcnt, null iov,
///   or unknown flags.
/// - [`Error::WouldBlock`] — non-blocking mode and data not available.
/// - [`Error::NotImplemented`] — VFS read path not yet wired.
pub fn sys_preadv2(fd: i32, iov: u64, iovcnt: i32, offset: i64, flags: i32) -> Result<i64> {
    let req = Preadv2Request::new(fd, iov, iovcnt, offset, flags);
    req.validate()?;
    do_preadv2(&req)
}

fn do_preadv2(req: &Preadv2Request) -> Result<i64> {
    let _ = req;
    // TODO: Gather iov array from user space, dispatch to the file's read_iter
    // operation with the specified offset and flags.
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_preadv2_syscall(fd: i32, iov: u64, iovcnt: i32, offset: i64, flags: i32) -> Result<i64> {
    sys_preadv2(fd, iov, iovcnt, offset, flags)
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
            sys_preadv2(-1, 1, 1, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn zero_iovcnt_rejected() {
        assert_eq!(
            sys_preadv2(0, 1, 0, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn too_many_iov_rejected() {
        assert_eq!(
            sys_preadv2(0, 1, UIO_MAXIOV + 1, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_iov_rejected() {
        assert_eq!(
            sys_preadv2(0, 0, 1, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(
            sys_preadv2(0, 1, 1, 0, 0x100).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn nowait_flag_detected() {
        let req = Preadv2Request::new(0, 1, 1, 0, RWF_NOWAIT);
        assert!(req.is_nowait());
    }

    #[test]
    fn negative_offset_uses_current_pos() {
        let req = Preadv2Request::new(0, 1, 1, -1, 0);
        assert!(req.use_current_pos());
    }
}
