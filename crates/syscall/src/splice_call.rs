// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `splice(2)` syscall handler — zero-copy data transfer between fd and pipe.
//!
//! `splice` moves data between a file descriptor and a pipe (or between two
//! pipes) without copying to user space.  At least one end must be a pipe.
//! The kernel moves pages directly between page caches where possible.
//!
//! # Linux man page
//!
//! `splice(2)`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// Move pages instead of copying (advisory; kernel may fall back to copy).
pub const SPLICE_F_MOVE: u32 = 0x01;
/// Do not block if pipe is empty / full; return `EAGAIN`.
pub const SPLICE_F_NONBLOCK: u32 = 0x02;
/// More data will follow — hint analogous to `MSG_MORE`.
pub const SPLICE_F_MORE: u32 = 0x04;
/// Gift the user pages to the pipe (used with `vmsplice`).
pub const SPLICE_F_GIFT: u32 = 0x08;

/// All valid splice flags.
const VALID_FLAGS: u32 = SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_GIFT;

// ---------------------------------------------------------------------------
// Splice endpoint kind
// ---------------------------------------------------------------------------

/// Identifies whether a splice endpoint is a pipe or a regular file/socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    /// The fd refers to a pipe.
    Pipe,
    /// The fd refers to a regular file or socket.
    File,
}

// ---------------------------------------------------------------------------
// Splice request
// ---------------------------------------------------------------------------

/// Validated `splice` request.
#[derive(Debug, Clone, Copy)]
pub struct SpliceRequest {
    /// Source file descriptor.
    pub fd_in: i32,
    /// Optional source offset; `None` means use current file position.
    pub off_in: Option<u64>,
    /// Destination file descriptor.
    pub fd_out: i32,
    /// Optional destination offset.
    pub off_out: Option<u64>,
    /// Maximum bytes to transfer.
    pub len: usize,
    /// Combination of `SPLICE_F_*` flags.
    pub flags: u32,
    /// Kind of the `fd_in` endpoint.
    pub in_kind: EndpointKind,
    /// Kind of the `fd_out` endpoint.
    pub out_kind: EndpointKind,
}

impl SpliceRequest {
    /// Create a new splice request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fd_in: i32,
        off_in: Option<u64>,
        fd_out: i32,
        off_out: Option<u64>,
        len: usize,
        flags: u32,
        in_kind: EndpointKind,
        out_kind: EndpointKind,
    ) -> Self {
        Self {
            fd_in,
            off_in,
            fd_out,
            off_out,
            len,
            flags,
            in_kind,
            out_kind,
        }
    }

    /// Returns `true` if the non-blocking flag is set.
    pub fn nonblock(&self) -> bool {
        self.flags & SPLICE_F_NONBLOCK != 0
    }

    /// Returns `true` if the move-pages hint is set.
    pub fn move_pages(&self) -> bool {
        self.flags & SPLICE_F_MOVE != 0
    }
}

// ---------------------------------------------------------------------------
// Splice outcome
// ---------------------------------------------------------------------------

/// Result of a splice operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpliceOutcome {
    /// `n` bytes were transferred.
    Transferred(usize),
    /// End of file on the source.
    Eof,
    /// Pipe full or empty and `SPLICE_F_NONBLOCK` is set.
    WouldBlock,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate `splice(2)` arguments.
///
/// At least one of `fd_in` or `fd_out` must be a pipe.
/// An offset cannot be specified for a pipe endpoint.
///
/// # Errors
///
/// | `Error`           | Condition                                          |
/// |-------------------|----------------------------------------------------|
/// | `InvalidArgument` | Both ends are non-pipe, or offset supplied for pipe |
/// | `InvalidArgument` | `len` is 0, bad fd, or unknown flags               |
pub fn validate_splice_args(
    fd_in: i32,
    off_in: Option<u64>,
    fd_out: i32,
    off_out: Option<u64>,
    len: usize,
    flags: u32,
    in_kind: EndpointKind,
    out_kind: EndpointKind,
) -> Result<()> {
    if fd_in < 0 || fd_out < 0 {
        return Err(Error::InvalidArgument);
    }
    if len == 0 {
        return Err(Error::InvalidArgument);
    }
    if flags & !VALID_FLAGS != 0 {
        return Err(Error::InvalidArgument);
    }
    // At least one end must be a pipe.
    if in_kind != EndpointKind::Pipe && out_kind != EndpointKind::Pipe {
        return Err(Error::InvalidArgument);
    }
    // Pipe endpoints cannot have an offset.
    if in_kind == EndpointKind::Pipe && off_in.is_some() {
        return Err(Error::InvalidArgument);
    }
    if out_kind == EndpointKind::Pipe && off_out.is_some() {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `splice(2)`.
///
/// Validates arguments and returns a `SpliceRequest` that the VFS layer can
/// execute.  The actual data movement is performed by the pipe subsystem in
/// cooperation with the page cache.
///
/// # Arguments
///
/// - `fd_in`    — source fd
/// - `off_in`   — source file offset (must be `None` for pipe endpoints)
/// - `fd_out`   — destination fd
/// - `off_out`  — destination file offset (must be `None` for pipe endpoints)
/// - `len`      — maximum bytes to transfer
/// - `flags`    — `SPLICE_F_*` flags
/// - `in_kind`  — whether `fd_in` is a pipe or file
/// - `out_kind` — whether `fd_out` is a pipe or file
///
/// # Errors
///
/// See [`validate_splice_args`].
#[allow(clippy::too_many_arguments)]
pub fn do_splice(
    fd_in: i32,
    off_in: Option<u64>,
    fd_out: i32,
    off_out: Option<u64>,
    len: usize,
    flags: u32,
    in_kind: EndpointKind,
    out_kind: EndpointKind,
) -> Result<SpliceRequest> {
    validate_splice_args(
        fd_in, off_in, fd_out, off_out, len, flags, in_kind, out_kind,
    )?;
    Ok(SpliceRequest::new(
        fd_in, off_in, fd_out, off_out, len, flags, in_kind, out_kind,
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_to_pipe_ok() {
        let req = do_splice(
            3,
            Some(0),
            4,
            None,
            4096,
            0,
            EndpointKind::File,
            EndpointKind::Pipe,
        )
        .unwrap();
        assert_eq!(req.len, 4096);
        assert!(!req.nonblock());
    }

    #[test]
    fn pipe_to_file_ok() {
        let req = do_splice(
            3,
            None,
            4,
            Some(1024),
            1024,
            SPLICE_F_MOVE,
            EndpointKind::Pipe,
            EndpointKind::File,
        )
        .unwrap();
        assert!(req.move_pages());
    }

    #[test]
    fn both_file_rejected() {
        assert_eq!(
            do_splice(
                3,
                Some(0),
                4,
                Some(0),
                512,
                0,
                EndpointKind::File,
                EndpointKind::File
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn pipe_with_offset_rejected() {
        assert_eq!(
            do_splice(
                3,
                Some(0),
                4,
                None,
                512,
                0,
                EndpointKind::Pipe,
                EndpointKind::Pipe
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn zero_len_rejected() {
        assert_eq!(
            do_splice(
                3,
                None,
                4,
                None,
                0,
                0,
                EndpointKind::Pipe,
                EndpointKind::Pipe
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn bad_flags_rejected() {
        assert_eq!(
            do_splice(
                3,
                None,
                4,
                None,
                512,
                0xFFFF_FF00,
                EndpointKind::Pipe,
                EndpointKind::Pipe
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn negative_fd_rejected() {
        assert_eq!(
            do_splice(
                -1,
                None,
                4,
                None,
                512,
                0,
                EndpointKind::Pipe,
                EndpointKind::Pipe
            ),
            Err(Error::InvalidArgument)
        );
    }
}
