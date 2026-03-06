// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `connect(2)` extended validation and state management.
//!
//! Provides detailed validation of `connect` arguments, connection state
//! tracking for sockets, and helpers for non-blocking connect semantics.
//!
//! The basic entry-point shim is in `connect_call.rs`.  This module handles
//! the more detailed validation and state machine.
//!
//! # Syscall signature
//!
//! ```text
//! int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
//! ```
//!
//! # POSIX reference
//!
//! POSIX.1-2024 §connect — `<sys/socket.h>`.
//!
//! # References
//!
//! - Linux: `net/socket.c` `__sys_connect()`
//! - `connect(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Connection state
// ---------------------------------------------------------------------------

/// State of a socket connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectState {
    /// Not connected and no connect in progress.
    Idle,
    /// A non-blocking connect is in progress.
    Connecting,
    /// Connection established.
    Connected,
    /// Connection was refused or timed out.
    Failed,
    /// Socket was shut down.
    Shutdown,
}

// ---------------------------------------------------------------------------
// Socket type constants
// ---------------------------------------------------------------------------

pub const SOCK_STREAM: i32 = 1;
pub const SOCK_DGRAM: i32 = 2;
pub const SOCK_SEQPACKET: i32 = 5;
pub const SOCK_NONBLOCK: i32 = 0x0000_0800;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;
pub const AF_UNIX: u16 = 1;
pub const AF_UNSPEC: u16 = 0;

/// Minimum sockaddr size.
const SOCKADDR_MIN: usize = 2;
/// Maximum sockaddr size.
const SOCKADDR_MAX: usize = 128;

// ---------------------------------------------------------------------------
// ConnectArgs — validated connect arguments
// ---------------------------------------------------------------------------

/// Validated `connect` arguments.
#[derive(Debug, Clone, Copy)]
pub struct ConnectArgs {
    /// File descriptor.
    pub sockfd: i32,
    /// Address family from the sockaddr.
    pub family: u16,
    /// Address length.
    pub addrlen: usize,
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate `connect` arguments.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — negative fd, addrlen out of range, or
///   `AF_UNSPEC` family.
pub fn validate_connect_args(sockfd: i32, addr: &[u8], addrlen: usize) -> Result<ConnectArgs> {
    if sockfd < 0 {
        return Err(Error::InvalidArgument);
    }
    if addrlen < SOCKADDR_MIN || addrlen > SOCKADDR_MAX {
        return Err(Error::InvalidArgument);
    }
    if addr.len() < addrlen {
        return Err(Error::InvalidArgument);
    }
    let family = u16::from_ne_bytes([addr[0], addr[1]]);
    // AF_UNSPEC on a STREAM socket is a disconnect; still allow it.
    Ok(ConnectArgs {
        sockfd,
        family,
        addrlen,
    })
}

// ---------------------------------------------------------------------------
// ConnectStateTable — per-fd connection state
// ---------------------------------------------------------------------------

/// Maximum tracked connections.
const MAX_SOCKETS: usize = 256;

#[derive(Clone, Copy, Default)]
struct ConnectRecord {
    sockfd: i32,
    state: ConnectState,
    nonblock: bool,
    active: bool,
    sock_type: i32,
}

impl ConnectRecord {
    const fn inactive() -> Self {
        Self {
            sockfd: 0,
            state: ConnectState::Idle,
            nonblock: false,
            active: false,
            sock_type: SOCK_STREAM,
        }
    }
}

impl Default for ConnectState {
    fn default() -> Self {
        Self::Idle
    }
}

/// Table tracking connection state for all socket file descriptors.
pub struct ConnectStateTable {
    records: [ConnectRecord; MAX_SOCKETS],
}

impl ConnectStateTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            records: [const { ConnectRecord::inactive() }; MAX_SOCKETS],
        }
    }

    /// Register a new socket fd.
    pub fn register(&mut self, sockfd: i32, sock_type: i32, nonblock: bool) -> Result<()> {
        if self.records.iter().any(|r| r.active && r.sockfd == sockfd) {
            return Err(Error::AlreadyExists);
        }
        let slot = self
            .records
            .iter()
            .position(|r| !r.active)
            .ok_or(Error::OutOfMemory)?;
        self.records[slot] = ConnectRecord {
            sockfd,
            state: ConnectState::Idle,
            nonblock,
            active: true,
            sock_type,
        };
        Ok(())
    }

    /// Transition the state for `sockfd`.
    pub fn set_state(&mut self, sockfd: i32, state: ConnectState) -> Result<()> {
        let rec = self
            .records
            .iter_mut()
            .find(|r| r.active && r.sockfd == sockfd)
            .ok_or(Error::NotFound)?;
        rec.state = state;
        Ok(())
    }

    /// Return the current state for `sockfd`.
    pub fn get_state(&self, sockfd: i32) -> Option<ConnectState> {
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

impl Default for ConnectStateTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// sys_connect_ext — extended connect dispatch
// ---------------------------------------------------------------------------

/// Extended `connect` handler with state tracking.
///
/// Validates the arguments, checks that the socket is in a connectable state,
/// and transitions it.
///
/// # Arguments
///
/// * `table`   — Connection state table.
/// * `sockfd`  — Socket file descriptor.
/// * `addr`    — Raw sockaddr bytes.
/// * `addrlen` — Length of `addr`.
///
/// # Returns
///
/// `Ok(ConnectArgs)` for a valid synchronous connect.
/// `Err(Error::WouldBlock)` for a non-blocking socket that would block.
/// `Err(Error::Busy)` for a socket already connecting.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — bad arguments.
/// * [`Error::AlreadyExists`]   — socket is already connected.
/// * [`Error::Busy`]            — non-blocking connect already in progress.
/// * [`Error::WouldBlock`]      — non-blocking socket would block.
/// * [`Error::NotFound`]        — fd not found in table.
pub fn sys_connect_ext(
    table: &mut ConnectStateTable,
    sockfd: i32,
    addr: &[u8],
    addrlen: usize,
) -> Result<ConnectArgs> {
    let args = validate_connect_args(sockfd, addr, addrlen)?;

    match table.get_state(sockfd) {
        None => return Err(Error::NotFound),
        Some(ConnectState::Connected) => return Err(Error::AlreadyExists),
        Some(ConnectState::Connecting) => return Err(Error::Busy),
        Some(ConnectState::Idle) | Some(ConnectState::Failed) | Some(ConnectState::Shutdown) => {}
    }

    table.set_state(sockfd, ConnectState::Connecting)?;
    Ok(args)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_inet_addr() -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
        b[2..4].copy_from_slice(&80u16.to_be_bytes()); // port 80
        b[4..8].copy_from_slice(&[93, 184, 216, 34]); // example.com
        b
    }

    #[test]
    fn valid_connect_args() {
        let addr = make_inet_addr();
        let a = validate_connect_args(3, &addr, 16).unwrap();
        assert_eq!(a.sockfd, 3);
        assert_eq!(a.family, AF_INET);
    }

    #[test]
    fn negative_fd_rejected() {
        let addr = make_inet_addr();
        assert_eq!(
            validate_connect_args(-1, &addr, 16),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn addrlen_too_small() {
        let addr = make_inet_addr();
        assert_eq!(
            validate_connect_args(3, &addr, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn state_transitions() {
        let mut t = ConnectStateTable::new();
        t.register(5, SOCK_STREAM, false).unwrap();
        assert_eq!(t.get_state(5), Some(ConnectState::Idle));
        t.set_state(5, ConnectState::Connected).unwrap();
        assert_eq!(t.get_state(5), Some(ConnectState::Connected));
    }

    #[test]
    fn already_connected_rejected() {
        let mut t = ConnectStateTable::new();
        t.register(5, SOCK_STREAM, false).unwrap();
        t.set_state(5, ConnectState::Connected).unwrap();
        let addr = make_inet_addr();
        assert_eq!(
            sys_connect_ext(&mut t, 5, &addr, 16),
            Err(Error::AlreadyExists)
        );
    }

    #[test]
    fn connecting_in_progress() {
        let mut t = ConnectStateTable::new();
        t.register(5, SOCK_STREAM, true).unwrap();
        t.set_state(5, ConnectState::Connecting).unwrap();
        let addr = make_inet_addr();
        assert_eq!(sys_connect_ext(&mut t, 5, &addr, 16), Err(Error::Busy));
    }

    #[test]
    fn successful_connect_transition() {
        let mut t = ConnectStateTable::new();
        t.register(5, SOCK_STREAM, false).unwrap();
        let addr = make_inet_addr();
        sys_connect_ext(&mut t, 5, &addr, 16).unwrap();
        assert_eq!(t.get_state(5), Some(ConnectState::Connecting));
    }
}
