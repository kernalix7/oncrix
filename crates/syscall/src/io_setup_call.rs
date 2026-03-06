// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `io_setup(2)` syscall handler — create an asynchronous I/O context.
//!
//! `io_setup` creates an asynchronous I/O context capable of holding up to
//! `nr_events` pending requests.  The opaque context handle is written to
//! `*ctxp`.
//!
//! # Syscall signature
//!
//! ```text
//! int io_setup(unsigned int nr_events, aio_context_t *ctxp);
//! ```
//!
//! Where `aio_context_t` is a `unsigned long`.
//!
//! # References
//!
//! - Linux: `fs/aio.c`
//! - `io_setup(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of AIO events a single context can queue.
pub const AIO_MAX_NR: u32 = 65536;

/// Minimum valid number of events for a new context.
pub const AIO_MIN_NR: u32 = 1;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// An opaque AIO context handle (kernel-internal ID).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AioContext(pub u64);

impl AioContext {
    /// Create a new context handle.
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Return the raw handle value.
    pub fn as_u64(self) -> u64 {
        self.0
    }

    /// Return whether this is the null/invalid context.
    pub fn is_null(self) -> bool {
        self.0 == 0
    }
}

/// Parameters for an `io_setup` call.
#[derive(Debug, Clone, Copy)]
pub struct IoSetupRequest {
    /// Maximum number of queued events.
    pub nr_events: u32,
    /// User-space pointer to write the `aio_context_t` handle into.
    pub ctxp: u64,
}

impl IoSetupRequest {
    /// Create a new request.
    pub const fn new(nr_events: u32, ctxp: u64) -> Self {
        Self { nr_events, ctxp }
    }

    /// Validate the request fields.
    pub fn validate(&self) -> Result<()> {
        if self.ctxp == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.nr_events < AIO_MIN_NR || self.nr_events > AIO_MAX_NR {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for IoSetupRequest {
    fn default() -> Self {
        Self::new(AIO_MIN_NR, 0)
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle the `io_setup(2)` syscall.
///
/// Creates an AIO context and writes the handle to `*ctxp`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null `ctxp`, or `nr_events` out of range.
/// - [`Error::OutOfMemory`] — kernel cannot allocate the context.
/// - [`Error::NotImplemented`] — AIO subsystem not yet wired.
pub fn sys_io_setup(nr_events: u32, ctxp: u64) -> Result<i64> {
    let req = IoSetupRequest::new(nr_events, ctxp);
    req.validate()?;
    do_io_setup(&req)
}

fn do_io_setup(req: &IoSetupRequest) -> Result<i64> {
    let _ = req;
    // TODO: Allocate a kioctx, map its ring buffer into the process address
    // space, and write the context handle to ctxp.
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_io_setup_syscall(nr_events: u32, ctxp: u64) -> Result<i64> {
    sys_io_setup(nr_events, ctxp)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_ctxp_rejected() {
        assert_eq!(sys_io_setup(1, 0).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn zero_nr_events_rejected() {
        assert_eq!(sys_io_setup(0, 0x1000).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn too_many_events_rejected() {
        assert_eq!(
            sys_io_setup(AIO_MAX_NR + 1, 0x1000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn valid_request_passes_validation() {
        let req = IoSetupRequest::new(64, 0x1000);
        assert!(req.validate().is_ok());
    }

    #[test]
    fn aio_context_null_check() {
        let ctx = AioContext::default();
        assert!(ctx.is_null());
    }

    #[test]
    fn aio_context_non_null() {
        let ctx = AioContext::new(42);
        assert!(!ctx.is_null());
        assert_eq!(ctx.as_u64(), 42);
    }
}
