// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `shutdown(2)` extended implementation.
//!
//! Validates the `how` argument, manages per-socket half-close state, and
//! provides helpers for querying whether a socket's read or write side is
//! still open.
//!
//! # Syscall signature
//!
//! ```text
//! int shutdown(int sockfd, int how);
//! ```
//!
//! # POSIX reference
//!
//! POSIX.1-2024 §shutdown — `<sys/socket.h>`.
//!
//! # References
//!
//! - Linux: `net/socket.c` `__sys_shutdown()`
//! - `shutdown(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// How constants
// ---------------------------------------------------------------------------

/// Stop receiving data.
pub const SHUT_RD: i32 = 0;
/// Stop sending data.
pub const SHUT_WR: i32 = 1;
/// Stop both sending and receiving.
pub const SHUT_RDWR: i32 = 2;

// ---------------------------------------------------------------------------
// ShutdownHow — decoded argument
// ---------------------------------------------------------------------------

/// Decoded `how` argument for `shutdown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownHow {
    /// Shut down the reading side.
    Rd,
    /// Shut down the writing side.
    Wr,
    /// Shut down both sides.
    RdWr,
}

impl ShutdownHow {
    /// Parse the raw `how` argument.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] for unrecognised values.
    pub fn from_raw(how: i32) -> Result<Self> {
        match how {
            SHUT_RD => Ok(Self::Rd),
            SHUT_WR => Ok(Self::Wr),
            SHUT_RDWR => Ok(Self::RdWr),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Return `true` if this shuts down the read side.
    pub const fn shuts_read(self) -> bool {
        matches!(self, Self::Rd | Self::RdWr)
    }

    /// Return `true` if this shuts down the write side.
    pub const fn shuts_write(self) -> bool {
        matches!(self, Self::Wr | Self::RdWr)
    }
}

// ---------------------------------------------------------------------------
// SocketHalfState — per-socket half-close tracking
// ---------------------------------------------------------------------------

/// Half-close state of a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SocketHalfState {
    /// Reading side has been shut down.
    pub rd_shutdown: bool,
    /// Writing side has been shut down.
    pub wr_shutdown: bool,
}

impl SocketHalfState {
    /// Apply a shutdown operation.
    pub fn apply(&mut self, how: ShutdownHow) {
        if how.shuts_read() {
            self.rd_shutdown = true;
        }
        if how.shuts_write() {
            self.wr_shutdown = true;
        }
    }

    /// Return `true` if the socket is fully shut down.
    pub const fn is_fully_shutdown(&self) -> bool {
        self.rd_shutdown && self.wr_shutdown
    }

    /// Return `true` if reads are still possible.
    pub const fn can_read(&self) -> bool {
        !self.rd_shutdown
    }

    /// Return `true` if writes are still possible.
    pub const fn can_write(&self) -> bool {
        !self.wr_shutdown
    }
}

// ---------------------------------------------------------------------------
// ShutdownTable — per-fd half-close state registry
// ---------------------------------------------------------------------------

/// Maximum tracked sockets.
const MAX_SOCKETS: usize = 256;

#[derive(Clone, Copy)]
struct ShutdownRecord {
    sockfd: i32,
    state: SocketHalfState,
    active: bool,
}

impl ShutdownRecord {
    const fn inactive() -> Self {
        Self {
            sockfd: 0,
            state: SocketHalfState {
                rd_shutdown: false,
                wr_shutdown: false,
            },
            active: false,
        }
    }
}

/// Registry of per-socket shutdown state.
pub struct ShutdownTable {
    records: [ShutdownRecord; MAX_SOCKETS],
}

impl ShutdownTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            records: [const { ShutdownRecord::inactive() }; MAX_SOCKETS],
        }
    }

    /// Register a socket fd.
    pub fn register(&mut self, sockfd: i32) -> Result<()> {
        if self.records.iter().any(|r| r.active && r.sockfd == sockfd) {
            return Err(Error::AlreadyExists);
        }
        let slot = self
            .records
            .iter()
            .position(|r| !r.active)
            .ok_or(Error::OutOfMemory)?;
        self.records[slot] = ShutdownRecord {
            sockfd,
            state: SocketHalfState::default(),
            active: true,
        };
        Ok(())
    }

    /// Apply a shutdown to `sockfd`.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] if `sockfd` is not registered.
    pub fn apply(&mut self, sockfd: i32, how: ShutdownHow) -> Result<SocketHalfState> {
        let rec = self
            .records
            .iter_mut()
            .find(|r| r.active && r.sockfd == sockfd)
            .ok_or(Error::NotFound)?;
        rec.state.apply(how);
        Ok(rec.state)
    }

    /// Return the current state for `sockfd`.
    pub fn get_state(&self, sockfd: i32) -> Option<SocketHalfState> {
        self.records
            .iter()
            .find(|r| r.active && r.sockfd == sockfd)
            .map(|r| r.state)
    }

    /// Remove a socket.
    pub fn remove(&mut self, sockfd: i32) -> bool {
        for rec in &mut self.records {
            if rec.active && rec.sockfd == sockfd {
                rec.active = false;
                return true;
            }
        }
        false
    }
}

impl Default for ShutdownTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// sys_shutdown_ext — extended entry point
// ---------------------------------------------------------------------------

/// Extended handler for `shutdown(2)`.
///
/// Validates `how` and applies the shutdown to the socket's half-state.
///
/// # Arguments
///
/// * `table`  — Shutdown state table.
/// * `sockfd` — Socket file descriptor.
/// * `how`    — Raw shutdown direction.
///
/// # Returns
///
/// The new half-close state after applying the shutdown.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — invalid `how` or negative `sockfd`.
/// * [`Error::NotFound`]        — `sockfd` not registered.
pub fn sys_shutdown_ext(
    table: &mut ShutdownTable,
    sockfd: i32,
    how: i32,
) -> Result<SocketHalfState> {
    if sockfd < 0 {
        return Err(Error::InvalidArgument);
    }
    let how = ShutdownHow::from_raw(how)?;
    table.apply(sockfd, how)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_rd() {
        let mut t = ShutdownTable::new();
        t.register(3).unwrap();
        let state = sys_shutdown_ext(&mut t, 3, SHUT_RD).unwrap();
        assert!(state.rd_shutdown);
        assert!(!state.wr_shutdown);
        assert!(state.can_write());
        assert!(!state.can_read());
    }

    #[test]
    fn shutdown_wr() {
        let mut t = ShutdownTable::new();
        t.register(3).unwrap();
        let state = sys_shutdown_ext(&mut t, 3, SHUT_WR).unwrap();
        assert!(!state.rd_shutdown);
        assert!(state.wr_shutdown);
    }

    #[test]
    fn shutdown_rdwr() {
        let mut t = ShutdownTable::new();
        t.register(3).unwrap();
        let state = sys_shutdown_ext(&mut t, 3, SHUT_RDWR).unwrap();
        assert!(state.is_fully_shutdown());
    }

    #[test]
    fn invalid_how() {
        let mut t = ShutdownTable::new();
        t.register(3).unwrap();
        assert_eq!(sys_shutdown_ext(&mut t, 3, 99), Err(Error::InvalidArgument));
    }

    #[test]
    fn fd_not_found() {
        let mut t = ShutdownTable::new();
        assert_eq!(sys_shutdown_ext(&mut t, 99, SHUT_RD), Err(Error::NotFound));
    }

    #[test]
    fn negative_fd() {
        let mut t = ShutdownTable::new();
        assert_eq!(
            sys_shutdown_ext(&mut t, -1, SHUT_RD),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn incremental_shutdown() {
        let mut t = ShutdownTable::new();
        t.register(5).unwrap();
        sys_shutdown_ext(&mut t, 5, SHUT_RD).unwrap();
        let state = sys_shutdown_ext(&mut t, 5, SHUT_WR).unwrap();
        assert!(state.is_fully_shutdown());
    }
}
