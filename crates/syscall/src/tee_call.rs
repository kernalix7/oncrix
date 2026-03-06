// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `tee(2)` syscall handler — duplicate pipe data without consuming it.
//!
//! `tee` copies data between two pipe file descriptors without removing it
//! from the source pipe.  Unlike `splice`, the source data remains readable
//! after `tee` — it is only consumed by a subsequent `read`/`splice`.
//!
//! Both `fd_in` and `fd_out` must refer to pipes.
//!
//! # Linux man page
//!
//! `tee(2)`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flags (shared with splice)
// ---------------------------------------------------------------------------

/// Do not block; return immediately if no data is available.
pub const SPLICE_F_NONBLOCK: u32 = 0x02;
/// More data will follow.
pub const SPLICE_F_MORE: u32 = 0x04;

/// All flags accepted by `tee`.
const VALID_FLAGS: u32 = SPLICE_F_NONBLOCK | SPLICE_F_MORE;

// ---------------------------------------------------------------------------
// Tee request
// ---------------------------------------------------------------------------

/// Validated `tee` request.
#[derive(Debug, Clone, Copy)]
pub struct TeeRequest {
    /// Source pipe file descriptor.
    pub fd_in: i32,
    /// Destination pipe file descriptor.
    pub fd_out: i32,
    /// Maximum bytes to duplicate.
    pub len: usize,
    /// Flags (`SPLICE_F_NONBLOCK`, `SPLICE_F_MORE`).
    pub flags: u32,
}

impl TeeRequest {
    /// Create a new tee request.
    pub fn new(fd_in: i32, fd_out: i32, len: usize, flags: u32) -> Self {
        Self {
            fd_in,
            fd_out,
            len,
            flags,
        }
    }

    /// Returns `true` if the non-blocking flag is set.
    pub fn nonblock(&self) -> bool {
        self.flags & SPLICE_F_NONBLOCK != 0
    }

    /// Returns `true` if the more-data hint is set.
    pub fn more(&self) -> bool {
        self.flags & SPLICE_F_MORE != 0
    }
}

// ---------------------------------------------------------------------------
// Tee outcome
// ---------------------------------------------------------------------------

/// Result of a `tee` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeeOutcome {
    /// `n` bytes were duplicated into `fd_out`.
    Duplicated(usize),
    /// Source pipe is empty and `SPLICE_F_NONBLOCK` is set.
    WouldBlock,
    /// Destination pipe is full.
    PipeFull,
}

// ---------------------------------------------------------------------------
// Pipe buffer state (minimal model for validation / simulation)
// ---------------------------------------------------------------------------

/// Minimal view of a pipe's buffer for `tee` accounting.
#[derive(Debug, Clone, Copy)]
pub struct PipeView {
    /// Current number of bytes available in the pipe buffer.
    pub available: usize,
    /// Total pipe buffer capacity.
    pub capacity: usize,
}

impl PipeView {
    /// Create a pipe view.
    pub fn new(available: usize, capacity: usize) -> Self {
        Self {
            available,
            capacity,
        }
    }

    /// Bytes of free space remaining in this pipe.
    pub fn free_space(&self) -> usize {
        self.capacity.saturating_sub(self.available)
    }

    /// Returns `true` if the pipe has data to read.
    pub fn has_data(&self) -> bool {
        self.available > 0
    }

    /// Returns `true` if the pipe is full.
    pub fn is_full(&self) -> bool {
        self.available >= self.capacity
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate `tee(2)` arguments.
///
/// # Errors
///
/// | `Error`           | Condition                                    |
/// |-------------------|----------------------------------------------|
/// | `InvalidArgument` | `fd_in` or `fd_out` < 0, len = 0, bad flags |
/// | `InvalidArgument` | `fd_in` == `fd_out`                          |
pub fn validate_tee_args(fd_in: i32, fd_out: i32, len: usize, flags: u32) -> Result<()> {
    if fd_in < 0 || fd_out < 0 {
        return Err(Error::InvalidArgument);
    }
    if fd_in == fd_out {
        return Err(Error::InvalidArgument);
    }
    if len == 0 {
        return Err(Error::InvalidArgument);
    }
    if flags & !VALID_FLAGS != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `tee(2)`.
///
/// Validates arguments and returns a `TeeRequest`.  The actual buffer
/// duplication is performed by the pipe subsystem: it copies page references
/// from the source pipe's ring buffer into the destination pipe, incrementing
/// the reference count rather than copying bytes.
///
/// # Arguments
///
/// - `fd_in`  — source pipe fd
/// - `fd_out` — destination pipe fd
/// - `len`    — maximum bytes to duplicate
/// - `flags`  — `SPLICE_F_NONBLOCK` and/or `SPLICE_F_MORE`
///
/// # Errors
///
/// | `Error`           | Condition                              |
/// |-------------------|----------------------------------------|
/// | `InvalidArgument` | Invalid arguments (see validation)     |
/// | `WouldBlock`      | Source pipe empty, non-blocking mode   |
pub fn do_tee(fd_in: i32, fd_out: i32, len: usize, flags: u32) -> Result<TeeRequest> {
    validate_tee_args(fd_in, fd_out, len, flags)?;
    Ok(TeeRequest::new(fd_in, fd_out, len, flags))
}

/// Simulate a `tee` transfer given current pipe views.
///
/// Returns how many bytes would be duplicated, or an appropriate outcome.
pub fn simulate_tee(req: &TeeRequest, src: &PipeView, dst: &PipeView) -> TeeOutcome {
    if !src.has_data() {
        return TeeOutcome::WouldBlock;
    }
    if dst.is_full() {
        return TeeOutcome::PipeFull;
    }
    let can_transfer = req.len.min(src.available).min(dst.free_space());
    TeeOutcome::Duplicated(can_transfer)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tee_ok() {
        let req = do_tee(3, 4, 4096, 0).unwrap();
        assert_eq!(req.fd_in, 3);
        assert_eq!(req.fd_out, 4);
        assert_eq!(req.len, 4096);
        assert!(!req.nonblock());
    }

    #[test]
    fn tee_nonblock_flag() {
        let req = do_tee(3, 4, 1024, SPLICE_F_NONBLOCK).unwrap();
        assert!(req.nonblock());
    }

    #[test]
    fn tee_same_fd_rejected() {
        assert_eq!(do_tee(3, 3, 512, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn tee_zero_len_rejected() {
        assert_eq!(do_tee(3, 4, 0, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn tee_negative_fd_rejected() {
        assert_eq!(do_tee(-1, 4, 512, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn tee_bad_flags_rejected() {
        assert_eq!(do_tee(3, 4, 512, 0xFF00_0000), Err(Error::InvalidArgument));
    }

    #[test]
    fn simulate_tee_normal() {
        let req = do_tee(3, 4, 4096, 0).unwrap();
        let src = PipeView::new(2048, 65536);
        let dst = PipeView::new(0, 65536);
        assert_eq!(simulate_tee(&req, &src, &dst), TeeOutcome::Duplicated(2048));
    }

    #[test]
    fn simulate_tee_empty_src() {
        let req = do_tee(3, 4, 4096, SPLICE_F_NONBLOCK).unwrap();
        let src = PipeView::new(0, 65536);
        let dst = PipeView::new(0, 65536);
        assert_eq!(simulate_tee(&req, &src, &dst), TeeOutcome::WouldBlock);
    }

    #[test]
    fn simulate_tee_full_dst() {
        let req = do_tee(3, 4, 4096, 0).unwrap();
        let src = PipeView::new(1024, 65536);
        let dst = PipeView::new(65536, 65536);
        assert_eq!(simulate_tee(&req, &src, &dst), TeeOutcome::PipeFull);
    }

    #[test]
    fn simulate_tee_limited_by_dst_space() {
        let req = do_tee(3, 4, 4096, 0).unwrap();
        let src = PipeView::new(4096, 65536);
        let dst = PipeView::new(65024, 65536); // 512 bytes free
        assert_eq!(simulate_tee(&req, &src, &dst), TeeOutcome::Duplicated(512));
    }
}
