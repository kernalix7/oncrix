// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `io_cancel(2)` syscall handler — cancel an outstanding asynchronous I/O request.
//!
//! `io_cancel` attempts to cancel the in-progress I/O operation identified by
//! the `iocb` pointer within the given AIO context.  If successful the
//! completion event is written to `*result`.
//!
//! # Syscall signature
//!
//! ```text
//! int io_cancel(aio_context_t ctx_id, struct iocb *iocb,
//!               struct io_event *result);
//! ```
//!
//! # References
//!
//! - Linux: `fs/aio.c`
//! - `io_cancel(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// A cancelled I/O completion event (same layout as `io_event`).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct IoCancelResult {
    /// Per-request data tag.
    pub data: u64,
    /// Pointer to the original `iocb`.
    pub obj: u64,
    /// Result code (`-ECANCELED` on successful cancel).
    pub res: i64,
    /// Secondary result.
    pub res2: i64,
}

impl IoCancelResult {
    /// Create a new zeroed result.
    pub const fn new() -> Self {
        Self {
            data: 0,
            obj: 0,
            res: 0,
            res2: 0,
        }
    }
}

/// Parameters for an `io_cancel` call.
#[derive(Debug, Clone, Copy)]
pub struct IoCancelRequest {
    /// AIO context handle.
    pub ctx_id: u64,
    /// User-space pointer to the `iocb` to cancel.
    pub iocb: u64,
    /// User-space pointer to write the cancellation result into.
    pub result: u64,
}

impl IoCancelRequest {
    /// Create a new request.
    pub const fn new(ctx_id: u64, iocb: u64, result: u64) -> Self {
        Self {
            ctx_id,
            iocb,
            result,
        }
    }

    /// Validate the request.
    pub fn validate(&self) -> Result<()> {
        if self.ctx_id == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.iocb == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.result == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for IoCancelRequest {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle the `io_cancel(2)` syscall.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null ctx, iocb, or result pointer.
/// - [`Error::NotFound`] — no matching pending operation was found.
/// - [`Error::NotImplemented`] — AIO subsystem not yet wired.
pub fn sys_io_cancel(ctx_id: u64, iocb: u64, result: u64) -> Result<i64> {
    let req = IoCancelRequest::new(ctx_id, iocb, result);
    req.validate()?;
    do_io_cancel(&req)
}

fn do_io_cancel(req: &IoCancelRequest) -> Result<i64> {
    let _ = req;
    // TODO: Search the kioctx for a pending iocb matching the pointer, cancel
    // it, and write the io_event result to user space.
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_io_cancel_syscall(ctx_id: u64, iocb: u64, result: u64) -> Result<i64> {
    sys_io_cancel(ctx_id, iocb, result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_ctx_rejected() {
        assert_eq!(sys_io_cancel(0, 1, 1).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn null_iocb_rejected() {
        assert_eq!(sys_io_cancel(1, 0, 1).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn null_result_rejected() {
        assert_eq!(sys_io_cancel(1, 1, 0).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn valid_request_reaches_subsystem() {
        assert_eq!(sys_io_cancel(1, 1, 1).unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn request_default_all_zero() {
        let req = IoCancelRequest::default();
        assert_eq!(req.ctx_id, 0);
        assert!(req.validate().is_err());
    }

    #[test]
    fn cancel_result_default() {
        let r = IoCancelResult::default();
        assert_eq!(r.res, 0);
    }
}
