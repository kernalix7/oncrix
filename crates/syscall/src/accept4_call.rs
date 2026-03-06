// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `accept4(2)` syscall handler — accept a connection with flags.
//!
//! `accept4` extends `accept` by allowing `SOCK_NONBLOCK` and `SOCK_CLOEXEC`
//! to be set atomically on the new socket, avoiding a race between `accept`
//! and a subsequent `fcntl`.
//!
//! # POSIX reference
//!
//! POSIX.1-2024 `accept()` — `susv5-html/functions/accept.html`.
//! Linux extension: `accept4(2)` adds `flags` argument.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Re-use address/socket constants from socket_calls
// ---------------------------------------------------------------------------

/// `accept4` flag — set O_NONBLOCK on the accepted socket.
pub const SOCK_NONBLOCK: i32 = 0x0000_0800;
/// `accept4` flag — set O_CLOEXEC on the accepted socket.
pub const SOCK_CLOEXEC: i32 = 0x0002_0000;

/// Maximum backlog queue length (upper bound accepted by `listen`).
pub const SOMAXCONN: u32 = 4096;

// ---------------------------------------------------------------------------
// Sockaddr storage
// ---------------------------------------------------------------------------

/// Generic socket address header (first two bytes common to all families).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockaddrStorage {
    /// Address family.
    pub sa_family: u16,
    /// Raw address bytes (up to 126 bytes to match `sockaddr_storage`).
    pub sa_data: [u8; 126],
}

impl Default for SockaddrStorage {
    fn default() -> Self {
        Self {
            sa_family: 0,
            sa_data: [0; 126],
        }
    }
}

impl SockaddrStorage {
    /// Create a zeroed storage.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the address family.
    pub fn family(&self) -> u16 {
        self.sa_family
    }

    /// Returns the raw data slice.
    pub fn data(&self) -> &[u8; 126] {
        &self.sa_data
    }
}

// ---------------------------------------------------------------------------
// Accept state machine
// ---------------------------------------------------------------------------

/// State of an `accept4` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptState {
    /// No pending connection; caller should block or retry.
    NoPendingConnection,
    /// A connection was successfully accepted.
    Accepted,
}

/// Descriptor returned when `accept4` succeeds.
#[derive(Debug, Clone, Copy)]
pub struct AcceptedSocket {
    /// Peer address filled in by the kernel.
    pub peer_addr: SockaddrStorage,
    /// Actual length of `peer_addr`.
    pub peer_addrlen: u32,
    /// Whether O_NONBLOCK should be set on the new fd.
    pub nonblock: bool,
    /// Whether O_CLOEXEC should be set on the new fd.
    pub cloexec: bool,
}

impl AcceptedSocket {
    /// Create a new accepted socket descriptor.
    pub fn new(peer_addr: SockaddrStorage, peer_addrlen: u32, flags: i32) -> Self {
        Self {
            peer_addr,
            peer_addrlen,
            nonblock: flags & SOCK_NONBLOCK != 0,
            cloexec: flags & SOCK_CLOEXEC != 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate `accept4` flags.
///
/// Only `SOCK_NONBLOCK` and `SOCK_CLOEXEC` are permitted.
///
/// # Errors
///
/// Returns `Error::InvalidArgument` if unknown flags are set.
pub fn validate_accept4_flags(flags: i32) -> Result<()> {
    let known = SOCK_NONBLOCK | SOCK_CLOEXEC;
    if flags & !known != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `accept4(2)`.
///
/// Validates `flags` and prepares an `AcceptedSocket` descriptor.
/// The caller is responsible for selecting the next pending connection from
/// the listening socket's accept queue and populating `peer_addr`.
///
/// # Arguments
///
/// - `sockfd`       — file descriptor of the listening socket
/// - `flags`        — combination of `SOCK_NONBLOCK` / `SOCK_CLOEXEC`
/// - `peer_addr`    — caller-provided storage to receive the peer address
/// - `peer_addrlen` — size of `peer_addr` on input; actual length on output
///
/// # Errors
///
/// | `Error`           | Condition                                      |
/// |-------------------|------------------------------------------------|
/// | `InvalidArgument` | `sockfd` < 0, `peer_addrlen` is 0, bad flags   |
/// | `WouldBlock`      | No pending connections (O_NONBLOCK)            |
/// | `Interrupted`     | Signal interrupted the wait                    |
pub fn do_accept4(
    sockfd: i32,
    flags: i32,
    peer_addr: SockaddrStorage,
    peer_addrlen: u32,
) -> Result<AcceptedSocket> {
    if sockfd < 0 {
        return Err(Error::InvalidArgument);
    }
    if peer_addrlen == 0 {
        return Err(Error::InvalidArgument);
    }
    validate_accept4_flags(flags)?;
    Ok(AcceptedSocket::new(peer_addr, peer_addrlen, flags))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_flags_accepted() {
        let addr = SockaddrStorage::default();
        let res = do_accept4(3, SOCK_NONBLOCK | SOCK_CLOEXEC, addr, 128);
        let sock = res.unwrap();
        assert!(sock.nonblock);
        assert!(sock.cloexec);
    }

    #[test]
    fn unknown_flag_rejected() {
        let addr = SockaddrStorage::default();
        assert_eq!(
            do_accept4(3, 0x1234_5678, addr, 128),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn negative_fd_rejected() {
        let addr = SockaddrStorage::default();
        assert_eq!(do_accept4(-1, 0, addr, 128), Err(Error::InvalidArgument));
    }

    #[test]
    fn zero_addrlen_rejected() {
        let addr = SockaddrStorage::default();
        assert_eq!(do_accept4(3, 0, addr, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn no_flags_ok() {
        let addr = SockaddrStorage::default();
        let sock = do_accept4(3, 0, addr, 128).unwrap();
        assert!(!sock.nonblock);
        assert!(!sock.cloexec);
    }
}
