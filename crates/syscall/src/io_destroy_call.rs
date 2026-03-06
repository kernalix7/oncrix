// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `io_destroy(2)` syscall handler — destroy an asynchronous I/O context.
//!
//! `io_destroy` cancels any outstanding asynchronous operations on the context
//! `ctx` and destroys it, releasing kernel resources.
//!
//! # Syscall signature
//!
//! ```text
//! int io_destroy(aio_context_t ctx);
//! ```
//!
//! Where `aio_context_t` is `unsigned long`.
//!
//! # References
//!
//! - Linux: `fs/aio.c`
//! - `io_destroy(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// An opaque AIO context handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AioContext(pub u64);

impl AioContext {
    /// Create a new handle.
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Return the raw value.
    pub fn as_u64(self) -> u64 {
        self.0
    }

    /// Return whether this is the null/invalid handle.
    pub fn is_null(self) -> bool {
        self.0 == 0
    }
}

/// Result of an `io_destroy` operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct IoDestroyResult {
    /// Number of in-flight operations cancelled.
    pub cancelled: u32,
}

impl IoDestroyResult {
    /// Create a new result.
    pub const fn new(cancelled: u32) -> Self {
        Self { cancelled }
    }
}

/// State of an AIO context before destruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AioContextState {
    /// Context is active with pending operations.
    Active,
    /// Context is idle with no pending operations.
    Idle,
    /// Context has already been destroyed.
    Destroyed,
}

impl Default for AioContextState {
    fn default() -> Self {
        Self::Active
    }
}

/// Metadata about an AIO context that can be queried before destruction.
#[derive(Debug, Clone, Copy, Default)]
pub struct AioContextInfo {
    /// The context handle.
    pub ctx: AioContext,
    /// Current lifecycle state of the context.
    pub state: AioContextState,
    /// Number of operations currently in flight.
    pub inflight: u32,
    /// Maximum queue depth this context was created with.
    pub max_nr: u32,
}

impl AioContextInfo {
    /// Create a new context info record.
    pub const fn new(ctx: AioContext, inflight: u32, max_nr: u32) -> Self {
        Self {
            ctx,
            state: AioContextState::Active,
            inflight,
            max_nr,
        }
    }

    /// Return whether the context is safe to destroy without cancellation.
    pub fn can_destroy_cleanly(&self) -> bool {
        self.inflight == 0
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle the `io_destroy(2)` syscall.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `ctx` is null (zero).
/// - [`Error::NotFound`] — `ctx` does not identify an AIO context owned by
///   the calling process.
/// - [`Error::NotImplemented`] — AIO subsystem not yet wired.
pub fn sys_io_destroy(ctx: u64) -> Result<i64> {
    if ctx == 0 {
        return Err(Error::InvalidArgument);
    }
    do_io_destroy(AioContext::new(ctx))
}

fn do_io_destroy(ctx: AioContext) -> Result<i64> {
    let _ = ctx;
    // TODO: Look up the kioctx by handle, cancel pending operations, wait for
    // completion, unmap the ring buffer, and free kernel structures.
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_io_destroy_syscall(ctx: u64) -> Result<i64> {
    sys_io_destroy(ctx)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_ctx_rejected() {
        assert_eq!(sys_io_destroy(0).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn valid_ctx_reaches_subsystem() {
        assert_eq!(sys_io_destroy(42).unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn aio_context_null() {
        assert!(AioContext::default().is_null());
    }

    #[test]
    fn aio_context_non_null() {
        let ctx = AioContext::new(1);
        assert!(!ctx.is_null());
    }

    #[test]
    fn result_default_zero() {
        let r = IoDestroyResult::default();
        assert_eq!(r.cancelled, 0);
    }

    #[test]
    fn result_new() {
        let r = IoDestroyResult::new(5);
        assert_eq!(r.cancelled, 5);
    }
}
