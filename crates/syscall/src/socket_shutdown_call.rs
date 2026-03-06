// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `shutdown(2)` syscall handler.
//!
//! Partially or fully disables communication on a socket without closing the
//! file descriptor.  This allows the caller to signal end-of-data to the peer
//! while still being able to receive remaining data, or vice-versa.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `shutdown()` specification.  Key behaviours:
//! - `SHUT_RD`   — no further receives are allowed; queued receive data is
//!   discarded.
//! - `SHUT_WR`   — no further sends are allowed; for TCP this triggers
//!   FIN transmission.
//! - `SHUT_RDWR` — both directions are shut down.
//! - `ENOTCONN`  — socket is not connected.
//! - `EINVAL`    — `how` is not one of the three valid values.
//! - Threads blocked in `read`/`recv` on the same socket must be woken with
//!   an error after `SHUT_RD`; threads blocked in `write`/`send` must be
//!   woken after `SHUT_WR`.
//!
//! # References
//!
//! - POSIX.1-2024: `shutdown()`
//! - Linux man pages: `shutdown(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Shut down the read half of the socket.
pub const SHUT_RD: i32 = 0;
/// Shut down the write half of the socket.
pub const SHUT_WR: i32 = 1;
/// Shut down both halves of the socket.
pub const SHUT_RDWR: i32 = 2;

// ---------------------------------------------------------------------------
// Socket shutdown state
// ---------------------------------------------------------------------------

/// Records which directions of a socket have been shut down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShutdownState {
    /// Read direction has been shut down.
    pub read_shut: bool,
    /// Write direction has been shut down.
    pub write_shut: bool,
}

impl ShutdownState {
    /// Returns `true` if both directions are shut down.
    pub const fn fully_shut(&self) -> bool {
        self.read_shut && self.write_shut
    }
}

/// Connection state of a socket with respect to `shutdown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    /// Socket has an active connection.
    Connected,
    /// Socket is not connected (only for connection-oriented types).
    NotConnected,
    /// Connectionless socket (UDP — always "connected" for shutdown purposes).
    Connectionless,
}

/// Mutable socket state passed to [`do_shutdown`].
#[derive(Debug)]
pub struct ShutdownSocket {
    /// Current connection state.
    pub conn_state: ConnState,
    /// Accumulated shutdown flags.
    pub shutdown: ShutdownState,
    /// Number of blocked readers waiting to be woken.
    pub blocked_readers: u32,
    /// Number of blocked writers waiting to be woken.
    pub blocked_writers: u32,
}

impl ShutdownSocket {
    /// Create a new connected socket with no shutdowns.
    pub const fn new_connected() -> Self {
        Self {
            conn_state: ConnState::Connected,
            shutdown: ShutdownState {
                read_shut: false,
                write_shut: false,
            },
            blocked_readers: 0,
            blocked_writers: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Wake-up notification
// ---------------------------------------------------------------------------

/// Records which classes of blocked waiters must be woken after a shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WakeupNotice {
    /// Blocked `read`/`recv` callers must be woken.
    pub wake_readers: bool,
    /// Blocked `write`/`send` callers must be woken.
    pub wake_writers: bool,
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `shutdown(2)`.
///
/// Updates the shutdown flags on `sock` and returns a [`WakeupNotice`]
/// indicating which classes of blocked waiters the kernel must wake.
///
/// # Errors
///
/// | `Error`       | Condition                                          |
/// |---------------|----------------------------------------------------|
/// | `InvalidArg`  | `how` is not `SHUT_RD`, `SHUT_WR`, or `SHUT_RDWR` |
/// | `NotConnected`| Socket is not connected (`ENOTCONN`)               |
pub fn do_shutdown(sock: &mut ShutdownSocket, how: i32) -> Result<WakeupNotice> {
    // Validate `how`.
    if how != SHUT_RD && how != SHUT_WR && how != SHUT_RDWR {
        return Err(Error::InvalidArgument);
    }

    // ENOTCONN for connection-oriented sockets that are not connected.
    if sock.conn_state == ConnState::NotConnected {
        return Err(Error::NotFound);
    }

    let mut notice = WakeupNotice::default();

    if (how == SHUT_RD || how == SHUT_RDWR) && !sock.shutdown.read_shut {
        sock.shutdown.read_shut = true;
        if sock.blocked_readers > 0 {
            notice.wake_readers = true;
        }
    }

    if (how == SHUT_WR || how == SHUT_RDWR) && !sock.shutdown.write_shut {
        sock.shutdown.write_shut = true;
        if sock.blocked_writers > 0 {
            notice.wake_writers = true;
        }
    }

    Ok(notice)
}

/// Returns `true` if a new `recv` call should immediately return `ESHUTDOWN`.
pub fn recv_forbidden(sock: &ShutdownSocket) -> bool {
    sock.shutdown.read_shut
}

/// Returns `true` if a new `send` call should immediately return `ESHUTDOWN`.
pub fn send_forbidden(sock: &ShutdownSocket) -> bool {
    sock.shutdown.write_shut
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_rd() {
        let mut s = ShutdownSocket::new_connected();
        s.blocked_readers = 2;
        let notice = do_shutdown(&mut s, SHUT_RD).unwrap();
        assert!(s.shutdown.read_shut);
        assert!(!s.shutdown.write_shut);
        assert!(notice.wake_readers);
        assert!(!notice.wake_writers);
    }

    #[test]
    fn shutdown_wr() {
        let mut s = ShutdownSocket::new_connected();
        s.blocked_writers = 1;
        let notice = do_shutdown(&mut s, SHUT_WR).unwrap();
        assert!(!s.shutdown.read_shut);
        assert!(s.shutdown.write_shut);
        assert!(!notice.wake_readers);
        assert!(notice.wake_writers);
    }

    #[test]
    fn shutdown_rdwr() {
        let mut s = ShutdownSocket::new_connected();
        s.blocked_readers = 1;
        s.blocked_writers = 1;
        let notice = do_shutdown(&mut s, SHUT_RDWR).unwrap();
        assert!(s.shutdown.fully_shut());
        assert!(notice.wake_readers);
        assert!(notice.wake_writers);
    }

    #[test]
    fn shutdown_invalid_how() {
        let mut s = ShutdownSocket::new_connected();
        assert_eq!(do_shutdown(&mut s, 99), Err(Error::InvalidArgument));
    }

    #[test]
    fn shutdown_not_connected() {
        let mut s = ShutdownSocket {
            conn_state: ConnState::NotConnected,
            shutdown: Default::default(),
            blocked_readers: 0,
            blocked_writers: 0,
        };
        assert_eq!(do_shutdown(&mut s, SHUT_RDWR), Err(Error::NotFound));
    }
}
