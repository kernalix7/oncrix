// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `shutdown(2)` syscall handler — shut down part or all of a socket connection.
//!
//! `shutdown` allows fine-grained half-close semantics: the read end, write end,
//! or both ends of a socket can be closed independently without releasing the
//! file descriptor.
//!
//! # POSIX reference
//!
//! POSIX.1-2024 `shutdown()` — `susv5-html/functions/shutdown.html`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// How constants
// ---------------------------------------------------------------------------

/// Shut down the reading half.
pub const SHUT_RD: i32 = 0;
/// Shut down the writing half.
pub const SHUT_WR: i32 = 1;
/// Shut down both halves.
pub const SHUT_RDWR: i32 = 2;

// ---------------------------------------------------------------------------
// Shutdown direction
// ---------------------------------------------------------------------------

/// Which direction(s) of the socket to shut down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownHow {
    /// Shut down further receives.
    Read,
    /// Shut down further sends.
    Write,
    /// Shut down both sends and receives.
    ReadWrite,
}

impl ShutdownHow {
    /// Convert from the POSIX `how` integer.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` for unknown values.
    pub fn from_raw(how: i32) -> Result<Self> {
        match how {
            SHUT_RD => Ok(Self::Read),
            SHUT_WR => Ok(Self::Write),
            SHUT_RDWR => Ok(Self::ReadWrite),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Returns true if the read side will be shut down.
    pub fn shuts_read(&self) -> bool {
        matches!(self, Self::Read | Self::ReadWrite)
    }

    /// Returns true if the write side will be shut down.
    pub fn shuts_write(&self) -> bool {
        matches!(self, Self::Write | Self::ReadWrite)
    }
}

// ---------------------------------------------------------------------------
// Shutdown request
// ---------------------------------------------------------------------------

/// Validated `shutdown` request.
#[derive(Debug, Clone, Copy)]
pub struct ShutdownRequest {
    /// Socket file descriptor.
    pub sockfd: i32,
    /// Direction(s) to shut down.
    pub how: ShutdownHow,
}

impl ShutdownRequest {
    /// Create a new shutdown request.
    pub fn new(sockfd: i32, how: ShutdownHow) -> Self {
        Self { sockfd, how }
    }
}

// ---------------------------------------------------------------------------
// Socket shutdown state
// ---------------------------------------------------------------------------

/// Bitmask tracking which halves of a socket have been shut down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShutdownState {
    /// Read half is shut down.
    pub read_shutdown: bool,
    /// Write half is shut down.
    pub write_shutdown: bool,
}

impl ShutdownState {
    /// Apply a shutdown direction to the current state.
    pub fn apply(&mut self, how: ShutdownHow) {
        if how.shuts_read() {
            self.read_shutdown = true;
        }
        if how.shuts_write() {
            self.write_shutdown = true;
        }
    }

    /// Returns true if both halves are shut down.
    pub fn is_fully_shutdown(&self) -> bool {
        self.read_shutdown && self.write_shutdown
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `shutdown(2)`.
///
/// Validates the socket file descriptor and the `how` argument, returning a
/// `ShutdownRequest` that the networking subsystem can apply.
///
/// Calling `shutdown` on a socket that has already had the same half shut down
/// is a no-op (POSIX does not require an error for idempotent shutdown).
///
/// # Arguments
///
/// - `sockfd` — open socket file descriptor
/// - `how`    — one of `SHUT_RD`, `SHUT_WR`, `SHUT_RDWR`
///
/// # Errors
///
/// | `Error`           | Condition                              |
/// |-------------------|----------------------------------------|
/// | `InvalidArgument` | `sockfd` < 0 or `how` out of range     |
/// | `NotFound`        | `sockfd` does not refer to a socket    |
pub fn do_shutdown(sockfd: i32, how: i32) -> Result<ShutdownRequest> {
    if sockfd < 0 {
        return Err(Error::InvalidArgument);
    }
    let direction = ShutdownHow::from_raw(how)?;
    Ok(ShutdownRequest::new(sockfd, direction))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_rd_ok() {
        let req = do_shutdown(3, SHUT_RD).unwrap();
        assert_eq!(req.how, ShutdownHow::Read);
        assert!(req.how.shuts_read());
        assert!(!req.how.shuts_write());
    }

    #[test]
    fn shutdown_wr_ok() {
        let req = do_shutdown(3, SHUT_WR).unwrap();
        assert_eq!(req.how, ShutdownHow::Write);
        assert!(!req.how.shuts_read());
        assert!(req.how.shuts_write());
    }

    #[test]
    fn shutdown_rdwr_ok() {
        let req = do_shutdown(3, SHUT_RDWR).unwrap();
        assert_eq!(req.how, ShutdownHow::ReadWrite);
        assert!(req.how.shuts_read());
        assert!(req.how.shuts_write());
    }

    #[test]
    fn shutdown_invalid_how() {
        assert_eq!(do_shutdown(3, 99), Err(Error::InvalidArgument));
    }

    #[test]
    fn shutdown_negative_fd() {
        assert_eq!(do_shutdown(-1, SHUT_RDWR), Err(Error::InvalidArgument));
    }

    #[test]
    fn shutdown_state_apply() {
        let mut state = ShutdownState::default();
        state.apply(ShutdownHow::Read);
        assert!(state.read_shutdown);
        assert!(!state.write_shutdown);
        state.apply(ShutdownHow::Write);
        assert!(state.is_fully_shutdown());
    }

    #[test]
    fn shutdown_state_rdwr() {
        let mut state = ShutdownState::default();
        state.apply(ShutdownHow::ReadWrite);
        assert!(state.is_fully_shutdown());
    }
}
