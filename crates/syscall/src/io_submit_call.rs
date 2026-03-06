// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `io_submit(2)` syscall handler — queue asynchronous I/O operations.
//!
//! `io_submit` queues up to `nr` asynchronous I/O control blocks (`iocb`)
//! pointed to by the array `iocbpp` into the AIO context `ctx_id`.
//!
//! # Syscall signature
//!
//! ```text
//! int io_submit(aio_context_t ctx_id, long nr, struct iocb **iocbpp);
//! ```
//!
//! # `iocb` operation codes (`aio_lio_opcode`)
//!
//! | Opcode | Value | Description |
//! |--------|-------|-------------|
//! | `IOCB_CMD_PREAD`  | 0 | Positional read |
//! | `IOCB_CMD_PWRITE` | 1 | Positional write |
//! | `IOCB_CMD_FSYNC`  | 2 | File sync |
//! | `IOCB_CMD_FDSYNC` | 3 | Data sync |
//! | `IOCB_CMD_POLL`   | 5 | Poll for events |
//! | `IOCB_CMD_NOOP`   | 6 | No-op |
//! | `IOCB_CMD_PREADV` | 7 | Positional scatter read |
//! | `IOCB_CMD_PWRITEV`| 8 | Positional gather write |
//!
//! # References
//!
//! - Linux: `fs/aio.c`, `include/uapi/linux/aio_abi.h`
//! - `io_submit(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// AIO opcode: positional read.
pub const IOCB_CMD_PREAD: u16 = 0;
/// AIO opcode: positional write.
pub const IOCB_CMD_PWRITE: u16 = 1;
/// AIO opcode: file sync (fsync).
pub const IOCB_CMD_FSYNC: u16 = 2;
/// AIO opcode: data sync (fdatasync).
pub const IOCB_CMD_FDSYNC: u16 = 3;
/// AIO opcode: poll for events.
pub const IOCB_CMD_POLL: u16 = 5;
/// AIO opcode: no-op.
pub const IOCB_CMD_NOOP: u16 = 6;
/// AIO opcode: positional scatter read.
pub const IOCB_CMD_PREADV: u16 = 7;
/// AIO opcode: positional gather write.
pub const IOCB_CMD_PWRITEV: u16 = 8;

/// Maximum number of iocbs that can be submitted in a single call.
pub const AIO_MAX_SUBMIT: usize = 4096;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Kernel representation of an AIO control block (simplified).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Iocb {
    /// Per-request data tag (returned in completion events).
    pub aio_data: u64,
    /// Operation code (one of `IOCB_CMD_*`).
    pub aio_lio_opcode: u16,
    /// Request priority.
    pub aio_reqprio: i16,
    /// File descriptor.
    pub aio_fildes: u32,
    /// Buffer pointer or iovec array pointer.
    pub aio_buf: u64,
    /// Length of buffer / number of iovec elements.
    pub aio_nbytes: u64,
    /// File offset for pread/pwrite.
    pub aio_offset: i64,
}

impl Iocb {
    /// Create a new zeroed control block.
    pub const fn new() -> Self {
        Self {
            aio_data: 0,
            aio_lio_opcode: 0,
            aio_reqprio: 0,
            aio_fildes: 0,
            aio_buf: 0,
            aio_nbytes: 0,
            aio_offset: 0,
        }
    }

    /// Return whether the opcode is recognized.
    pub fn is_valid_opcode(&self) -> bool {
        matches!(
            self.aio_lio_opcode,
            IOCB_CMD_PREAD
                | IOCB_CMD_PWRITE
                | IOCB_CMD_FSYNC
                | IOCB_CMD_FDSYNC
                | IOCB_CMD_POLL
                | IOCB_CMD_NOOP
                | IOCB_CMD_PREADV
                | IOCB_CMD_PWRITEV
        )
    }
}

/// Parameters for an `io_submit` call.
#[derive(Debug, Clone, Copy)]
pub struct IoSubmitRequest {
    /// AIO context handle.
    pub ctx_id: u64,
    /// Number of iocb pointers in the array.
    pub nr: i64,
    /// User-space pointer to array of iocb pointers.
    pub iocbpp: u64,
}

impl IoSubmitRequest {
    /// Create a new request.
    pub const fn new(ctx_id: u64, nr: i64, iocbpp: u64) -> Self {
        Self { ctx_id, nr, iocbpp }
    }

    /// Validate the request.
    pub fn validate(&self) -> Result<()> {
        if self.ctx_id == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.nr < 0 || (self.nr as usize) > AIO_MAX_SUBMIT {
            return Err(Error::InvalidArgument);
        }
        if self.nr > 0 && self.iocbpp == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for IoSubmitRequest {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle the `io_submit(2)` syscall.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null ctx, negative nr, too many iocbs, or
///   null iocbpp when nr > 0.
/// - [`Error::NotFound`] — `ctx_id` is not a valid context for this process.
/// - [`Error::NotImplemented`] — AIO subsystem not yet wired.
pub fn sys_io_submit(ctx_id: u64, nr: i64, iocbpp: u64) -> Result<i64> {
    let req = IoSubmitRequest::new(ctx_id, nr, iocbpp);
    req.validate()?;
    // Submitting zero operations is a no-op; return 0.
    if nr == 0 {
        return Ok(0);
    }
    do_io_submit(&req)
}

fn do_io_submit(req: &IoSubmitRequest) -> Result<i64> {
    let _ = req;
    // TODO: Copy iocb pointers from user space, validate each iocb, and
    // enqueue operations into the kioctx.
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_io_submit_syscall(ctx_id: u64, nr: i64, iocbpp: u64) -> Result<i64> {
    sys_io_submit(ctx_id, nr, iocbpp)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_ctx_rejected() {
        assert_eq!(sys_io_submit(0, 1, 1).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn negative_nr_rejected() {
        assert_eq!(sys_io_submit(1, -1, 1).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn too_many_iocbs_rejected() {
        assert_eq!(
            sys_io_submit(1, AIO_MAX_SUBMIT as i64 + 1, 1).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_iocbpp_with_nr_gt_zero_rejected() {
        assert_eq!(sys_io_submit(1, 1, 0).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn zero_nr_returns_ok_zero() {
        assert_eq!(sys_io_submit(1, 0, 0).unwrap(), 0);
    }

    #[test]
    fn iocb_opcode_validity() {
        let mut iocb = Iocb::new();
        iocb.aio_lio_opcode = IOCB_CMD_PREAD;
        assert!(iocb.is_valid_opcode());
        iocb.aio_lio_opcode = 99;
        assert!(!iocb.is_valid_opcode());
    }
}
