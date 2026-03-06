// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `preadv2(2)` and `pwritev2(2)` positioned scatter-gather I/O syscall handlers.
//!
//! `preadv`/`pwritev` are like `readv`/`writev` but with an explicit file
//! offset (without changing the file position).  `preadv2`/`pwritev2` add
//! a `flags` argument for per-call I/O control hints.
//!
//! # POSIX Conformance
//!
//! `preadv` and `pwritev` are Linux extensions present on most UNIX systems;
//! `preadv2`/`pwritev2` are Linux-specific.  Key behaviours:
//! - Offset `-1` means "use current file position" (preadv2 extension).
//! - `RWF_NOWAIT` — do not block; return `EAGAIN` if I/O would block.
//! - `RWF_DSYNC`  — data-sync on write (like `O_DSYNC`).
//! - `RWF_SYNC`   — full sync on write (like `O_SYNC`).
//! - `RWF_HIPRI`  — high-priority I/O (polling mode).
//! - `RWF_APPEND` — append-mode write (offset ignored).
//! - Invalid flags bits → `EINVAL`.
//! - Offset must not be negative unless it is `-1` (current position).
//!
//! # References
//!
//! - Linux man pages: `preadv2(2)`, `pwritev2(2)`

use crate::readv_call::{Iovec, UIO_MAXIOV, validate_iovec};
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// RWF flags
// ---------------------------------------------------------------------------

/// I/O hint: high-priority (polling mode, no interrupt).
pub const RWF_HIPRI: u32 = 0x0000_0001;
/// Write hint: data-sync semantics.
pub const RWF_DSYNC: u32 = 0x0000_0002;
/// Read/write hint: don't wait if I/O would block.
pub const RWF_NOWAIT: u32 = 0x0000_0008;
/// Write hint: full sync semantics.
pub const RWF_SYNC: u32 = 0x0000_0004;
/// Write hint: append mode (ignore offset).
pub const RWF_APPEND: u32 = 0x0000_0010;

/// All known RWF flag bits.
const RWF_KNOWN: u32 = RWF_HIPRI | RWF_DSYNC | RWF_SYNC | RWF_NOWAIT | RWF_APPEND;

/// Sentinel offset meaning "use current file position".
pub const OFFSET_CURRENT: i64 = -1;

// ---------------------------------------------------------------------------
// Parsed flags
// ---------------------------------------------------------------------------

/// Decoded RWF flags for a preadv2/pwritev2 call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RwfFlags {
    /// High-priority I/O.
    pub hipri: bool,
    /// Data-sync write.
    pub dsync: bool,
    /// Full-sync write.
    pub sync: bool,
    /// Non-blocking I/O.
    pub nowait: bool,
    /// Append-mode write.
    pub append: bool,
}

impl RwfFlags {
    /// Parse raw flags, rejecting unknown bits.
    pub fn parse(raw: u32) -> Result<Self> {
        if raw & !RWF_KNOWN != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            hipri: raw & RWF_HIPRI != 0,
            dsync: raw & RWF_DSYNC != 0,
            sync: raw & RWF_SYNC != 0,
            nowait: raw & RWF_NOWAIT != 0,
            append: raw & RWF_APPEND != 0,
        })
    }
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Outcome of a `preadv2` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreadvResult {
    /// Bytes read.
    pub bytes_read: usize,
    /// New file offset after the read (if not using current-position).
    pub new_offset: i64,
    /// Whether the call was non-blocking and would have blocked.
    pub would_block: bool,
}

/// Outcome of a `pwritev2` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PwritevResult {
    /// Bytes written.
    pub bytes_written: usize,
    /// New file offset after the write.
    pub new_offset: i64,
    /// Whether the call was non-blocking and would have blocked.
    pub would_block: bool,
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `preadv2(2)`.
///
/// Reads from `fd` at `offset` (or current position if `offset == -1`) into
/// the scatter buffers described by `iov`.
///
/// `available` simulates the number of bytes the underlying file/device has
/// ready to provide.  In a real kernel this comes from the VFS.
///
/// # Errors
///
/// | `Error`    | Condition                                              |
/// |------------|--------------------------------------------------------|
/// | `InvalidArg` | Unknown flags bits                                   |
/// | `InvalidArg` | `offset` is negative and not `OFFSET_CURRENT`        |
/// | `InvalidArg` | iovec validation failure (see `validate_iovec`)       |
/// | `WouldBlock` | `RWF_NOWAIT` and no data immediately available        |
pub fn do_preadv2(
    _fd: i32,
    iov: &[Iovec],
    offset: i64,
    flags: u32,
    current_pos: i64,
    available: usize,
) -> Result<PreadvResult> {
    let rwf = RwfFlags::parse(flags)?;

    if offset < 0 && offset != OFFSET_CURRENT {
        return Err(Error::InvalidArgument);
    }

    let effective_offset = if offset == OFFSET_CURRENT {
        current_pos
    } else {
        offset
    };

    // Validate iov (also checks iovcnt bounds via slice length).
    if iov.len() > UIO_MAXIOV {
        return Err(Error::InvalidArgument);
    }
    let total_req = validate_iovec(iov)?;

    if rwf.nowait && available == 0 {
        return Ok(PreadvResult {
            bytes_read: 0,
            new_offset: effective_offset,
            would_block: true,
        });
    }

    let bytes_read = total_req.min(available);
    let new_offset = effective_offset + bytes_read as i64;

    Ok(PreadvResult {
        bytes_read,
        new_offset,
        would_block: false,
    })
}

/// Handler for `pwritev2(2)`.
///
/// Writes from the scatter buffers described by `iov` to `fd` at `offset`
/// (or appends if `RWF_APPEND` is set).
///
/// `file_size` is the current file size (used to compute append offset).
///
/// # Errors
///
/// | `Error`    | Condition                                              |
/// |------------|--------------------------------------------------------|
/// | `InvalidArg` | Unknown flags bits                                   |
/// | `InvalidArg` | `offset` is negative and not `OFFSET_CURRENT`        |
/// | `InvalidArg` | iovec validation failure                               |
/// | `WouldBlock` | `RWF_NOWAIT` and write would block                    |
pub fn do_pwritev2(
    _fd: i32,
    iov: &[Iovec],
    offset: i64,
    flags: u32,
    current_pos: i64,
    file_size: i64,
    would_block_sim: bool,
) -> Result<PwritevResult> {
    let rwf = RwfFlags::parse(flags)?;

    if offset < 0 && offset != OFFSET_CURRENT && !rwf.append {
        return Err(Error::InvalidArgument);
    }

    if iov.len() > UIO_MAXIOV {
        return Err(Error::InvalidArgument);
    }
    let total = validate_iovec(iov)?;

    if rwf.nowait && would_block_sim {
        let eff = if rwf.append {
            file_size
        } else if offset == OFFSET_CURRENT {
            current_pos
        } else {
            offset
        };
        return Ok(PwritevResult {
            bytes_written: 0,
            new_offset: eff,
            would_block: true,
        });
    }

    let write_offset = if rwf.append {
        file_size
    } else if offset == OFFSET_CURRENT {
        current_pos
    } else {
        offset
    };

    let new_offset = write_offset + total as i64;
    Ok(PwritevResult {
        bytes_written: total,
        new_offset,
        would_block: false,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn iov2() -> [Iovec; 2] {
        [Iovec::new(0x1000, 64), Iovec::new(0x2000, 64)]
    }

    #[test]
    fn preadv2_basic() {
        let res = do_preadv2(3, &iov2(), 100, 0, 0, 200).unwrap();
        assert_eq!(res.bytes_read, 128);
        assert_eq!(res.new_offset, 228);
    }

    #[test]
    fn preadv2_current_pos() {
        let res = do_preadv2(3, &iov2(), OFFSET_CURRENT, 0, 50, 200).unwrap();
        assert_eq!(res.new_offset, 178);
    }

    #[test]
    fn preadv2_nowait_would_block() {
        let res = do_preadv2(3, &iov2(), 0, RWF_NOWAIT, 0, 0).unwrap();
        assert!(res.would_block);
    }

    #[test]
    fn pwritev2_append() {
        let res = do_pwritev2(3, &iov2(), 0, RWF_APPEND, 0, 1000, false).unwrap();
        assert_eq!(res.bytes_written, 128);
        assert_eq!(res.new_offset, 1128);
    }

    #[test]
    fn invalid_flags() {
        assert_eq!(
            do_preadv2(3, &iov2(), 0, 0xDEAD_BEEF, 0, 100),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn negative_offset_invalid() {
        assert_eq!(
            do_preadv2(3, &iov2(), -5, 0, 0, 100),
            Err(Error::InvalidArgument)
        );
    }
}
