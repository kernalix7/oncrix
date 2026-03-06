// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `pwritev(2)` / `pwritev2(2)` syscall handler — scatter write at offset.
//!
//! `pwritev` writes data from multiple buffers to a file descriptor at a
//! specified offset without changing the file position.  `pwritev2` adds
//! additional flags for controlling write behavior.
//!
//! # POSIX reference
//!
//! `pwritev` is POSIX.1-2008 (XSI extension); see `writev(3p)`.
//! `pwritev2` is Linux-specific: `pwritev2(2)` man page.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flags for pwritev2
// ---------------------------------------------------------------------------

/// Per-operation hint: RWF_HIPRI — high-priority I/O; poll if possible.
pub const RWF_HIPRI: u32 = 0x0000_0001;
/// Per-operation hint: RWF_DSYNC — O_DSYNC semantics.
pub const RWF_DSYNC: u32 = 0x0000_0002;
/// Per-operation hint: RWF_SYNC — O_SYNC semantics.
pub const RWF_SYNC: u32 = 0x0000_0004;
/// Per-operation hint: RWF_NOWAIT — return EAGAIN instead of blocking.
pub const RWF_NOWAIT: u32 = 0x0000_0008;
/// Per-operation hint: RWF_APPEND — append data to the end of the file.
pub const RWF_APPEND: u32 = 0x0000_0010;
/// Per-operation hint: RWF_NOAPPEND — ignored if `O_APPEND` is set.
pub const RWF_NOAPPEND: u32 = 0x0000_0020;

/// All valid `pwritev2` flags.
const VALID_FLAGS: u32 = RWF_HIPRI | RWF_DSYNC | RWF_SYNC | RWF_NOWAIT | RWF_APPEND | RWF_NOAPPEND;

/// Maximum number of `iovec` elements in a single call.
pub const UIO_MAXIOV: usize = 1024;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// An I/O vector element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct IoVec {
    /// User-space pointer to the buffer.
    pub iov_base: usize,
    /// Length of the buffer in bytes.
    pub iov_len: usize,
}

impl IoVec {
    /// Construct a new `IoVec`.
    pub const fn new(iov_base: usize, iov_len: usize) -> Self {
        Self { iov_base, iov_len }
    }

    /// Return `true` if this vector element is empty.
    pub fn is_empty(&self) -> bool {
        self.iov_len == 0
    }
}

/// Validated `pwritev` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PwritevRequest {
    /// File descriptor.
    pub fd: i32,
    /// User-space pointer to the `iovec` array.
    pub iov: usize,
    /// Number of `iovec` elements.
    pub iovcnt: usize,
    /// File offset at which to write.
    pub offset: i64,
    /// Flags (for `pwritev2`; zero for plain `pwritev`).
    pub flags: u32,
}

impl PwritevRequest {
    /// Construct a new request.
    pub const fn new(fd: i32, iov: usize, iovcnt: usize, offset: i64, flags: u32) -> Self {
        Self {
            fd,
            iov,
            iovcnt,
            offset,
            flags,
        }
    }

    /// Return `true` if this is a `pwritev2` call (flags were provided).
    pub fn is_pwritev2(&self) -> bool {
        self.flags != 0
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `pwritev(2)` and `pwritev2(2)`.
///
/// Validates arguments and returns a structured request.  For `pwritev` the
/// `flags` argument should be 0.  For `pwritev2` any of the `RWF_*` flags
/// are accepted.
///
/// # Arguments
///
/// - `fd`     — writable file descriptor
/// - `iov`    — user-space pointer to the `iovec` array
/// - `iovcnt` — number of elements in `iov`
/// - `offset` — file offset (`-1` uses the current file position for `pwritev2`)
/// - `flags`  — `RWF_*` flags (must be 0 for plain `pwritev`)
///
/// # Errors
///
/// | `Error`           | Condition                                          |
/// |-------------------|----------------------------------------------------|
/// | `InvalidArgument` | Bad fd, null iov, iovcnt==0 or > UIO_MAXIOV, bad flags |
/// | `IoError`         | Write failed                                       |
pub fn do_pwritev(
    fd: i32,
    iov: usize,
    iovcnt: usize,
    offset: i64,
    flags: u32,
) -> Result<PwritevRequest> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    if iov == 0 {
        return Err(Error::InvalidArgument);
    }
    if iovcnt == 0 || iovcnt > UIO_MAXIOV {
        return Err(Error::InvalidArgument);
    }
    if flags & !VALID_FLAGS != 0 {
        return Err(Error::InvalidArgument);
    }
    // Offset -1 is only allowed in pwritev2.
    if offset < -1 {
        return Err(Error::InvalidArgument);
    }
    if offset == -1 && flags == 0 {
        // Plain pwritev requires a non-negative offset.
        return Err(Error::InvalidArgument);
    }
    Ok(PwritevRequest::new(fd, iov, iovcnt, offset, flags))
}

/// Return `true` if `RWF_SYNC` semantics are requested.
pub fn is_sync(flags: u32) -> bool {
    flags & (RWF_SYNC | RWF_DSYNC) != 0
}

/// Return `true` if the call should not block.
pub fn is_nowait(flags: u32) -> bool {
    flags & RWF_NOWAIT != 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_pwritev_ok() {
        let req = do_pwritev(3, 0xDEAD, 4, 0, 0).unwrap();
        assert_eq!(req.fd, 3);
        assert_eq!(req.iovcnt, 4);
        assert!(!req.is_pwritev2());
    }

    #[test]
    fn pwritev2_with_flags_ok() {
        let req = do_pwritev(3, 0xDEAD, 1, 0, RWF_DSYNC).unwrap();
        assert!(req.is_pwritev2());
        assert!(is_sync(req.flags));
    }

    #[test]
    fn offset_minus1_allowed_for_pwritev2() {
        let req = do_pwritev(3, 0xDEAD, 1, -1, RWF_NOWAIT).unwrap();
        assert_eq!(req.offset, -1);
    }

    #[test]
    fn offset_minus1_rejected_for_pwritev() {
        assert_eq!(do_pwritev(3, 0xDEAD, 1, -1, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn negative_fd_rejected() {
        assert_eq!(do_pwritev(-1, 0xDEAD, 1, 0, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn null_iov_rejected() {
        assert_eq!(do_pwritev(3, 0, 1, 0, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn zero_iovcnt_rejected() {
        assert_eq!(do_pwritev(3, 0xDEAD, 0, 0, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn too_many_iov_rejected() {
        assert_eq!(
            do_pwritev(3, 0xDEAD, UIO_MAXIOV + 1, 0, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(
            do_pwritev(3, 0xDEAD, 1, 0, 0xFF00),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn nowait_detection() {
        assert!(is_nowait(RWF_NOWAIT));
        assert!(!is_nowait(RWF_DSYNC));
    }
}
