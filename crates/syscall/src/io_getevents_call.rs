// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `io_getevents(2)` syscall handler — read completion events from an AIO ring.
//!
//! `io_getevents` reads up to `max_events` completed I/O events from the AIO
//! context ring buffer.  It waits until at least `min_nr` events are available
//! or the optional `timeout` expires.
//!
//! # Syscall signature
//!
//! ```text
//! int io_getevents(aio_context_t ctx_id, long min_nr, long max_nr,
//!                  struct io_event *events, struct timespec *timeout);
//! ```
//!
//! # References
//!
//! - Linux: `fs/aio.c`, `include/uapi/linux/aio_abi.h`
//! - `io_getevents(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of events retrievable in a single call.
pub const AIO_MAX_EVENTS: i64 = 4096;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// A single completed I/O event (mirrors `struct io_event`).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct IoEvent {
    /// Request data tag (from `iocb.aio_data`).
    pub data: u64,
    /// Pointer to the original iocb.
    pub obj: u64,
    /// Result code (bytes transferred or negative errno).
    pub res: i64,
    /// Secondary result (e.g. extended error info).
    pub res2: i64,
}

impl IoEvent {
    /// Create a new zeroed event.
    pub const fn new() -> Self {
        Self {
            data: 0,
            obj: 0,
            res: 0,
            res2: 0,
        }
    }

    /// Return whether this event represents an error.
    pub fn is_error(&self) -> bool {
        self.res < 0
    }
}

/// Parameters for an `io_getevents` call.
#[derive(Debug, Clone, Copy)]
pub struct IoGeteventsRequest {
    /// AIO context handle.
    pub ctx_id: u64,
    /// Minimum number of events to wait for.
    pub min_nr: i64,
    /// Maximum number of events to retrieve.
    pub max_nr: i64,
    /// User-space pointer to output `io_event` array.
    pub events: u64,
    /// Optional user-space pointer to `struct timespec` timeout (0 = none).
    pub timeout: u64,
}

impl IoGeteventsRequest {
    /// Create a new request.
    pub const fn new(ctx_id: u64, min_nr: i64, max_nr: i64, events: u64, timeout: u64) -> Self {
        Self {
            ctx_id,
            min_nr,
            max_nr,
            events,
            timeout,
        }
    }

    /// Validate the request fields.
    pub fn validate(&self) -> Result<()> {
        if self.ctx_id == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.min_nr < 0 || self.max_nr < 0 {
            return Err(Error::InvalidArgument);
        }
        if self.min_nr > self.max_nr {
            return Err(Error::InvalidArgument);
        }
        if self.max_nr > AIO_MAX_EVENTS {
            return Err(Error::InvalidArgument);
        }
        if self.max_nr > 0 && self.events == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for IoGeteventsRequest {
    fn default() -> Self {
        Self::new(0, 0, 0, 0, 0)
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle the `io_getevents(2)` syscall.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null ctx, negative counts, min > max, or
///   null events pointer with max_nr > 0.
/// - [`Error::NotFound`] — ctx_id is not valid.
/// - [`Error::Interrupted`] — interrupted by a signal before min_nr was met.
/// - [`Error::NotImplemented`] — AIO subsystem not yet wired.
pub fn sys_io_getevents(
    ctx_id: u64,
    min_nr: i64,
    max_nr: i64,
    events: u64,
    timeout: u64,
) -> Result<i64> {
    let req = IoGeteventsRequest::new(ctx_id, min_nr, max_nr, events, timeout);
    req.validate()?;
    if max_nr == 0 {
        return Ok(0);
    }
    do_io_getevents(&req)
}

fn do_io_getevents(req: &IoGeteventsRequest) -> Result<i64> {
    let _ = req;
    // TODO: Poll the context ring buffer, optionally wait for min_nr events,
    // copy completed events to user space, and return the count.
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_io_getevents_syscall(
    ctx_id: u64,
    min_nr: i64,
    max_nr: i64,
    events: u64,
    timeout: u64,
) -> Result<i64> {
    sys_io_getevents(ctx_id, min_nr, max_nr, events, timeout)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_ctx_rejected() {
        assert_eq!(
            sys_io_getevents(0, 0, 1, 1, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn min_greater_than_max_rejected() {
        assert_eq!(
            sys_io_getevents(1, 5, 3, 1, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn too_many_events_rejected() {
        assert_eq!(
            sys_io_getevents(1, 0, AIO_MAX_EVENTS + 1, 1, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_events_with_max_nr_rejected() {
        assert_eq!(
            sys_io_getevents(1, 0, 1, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn max_nr_zero_returns_ok() {
        assert_eq!(sys_io_getevents(1, 0, 0, 0, 0).unwrap(), 0);
    }

    #[test]
    fn io_event_error_check() {
        let mut ev = IoEvent::new();
        ev.res = -5;
        assert!(ev.is_error());
        ev.res = 100;
        assert!(!ev.is_error());
    }

    #[test]
    fn request_default() {
        let req = IoGeteventsRequest::default();
        assert_eq!(req.ctx_id, 0);
    }
}
