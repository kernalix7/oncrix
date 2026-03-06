// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `socketpair(2)` syscall handler — extended implementation.
//!
//! Creates a pair of connected sockets in the specified domain.  Both ends
//! are identical and fully bidirectional.  Primarily used with `AF_UNIX`
//! and `AF_INET` in local loopback scenarios.
//!
//! # Syscall signature
//!
//! ```text
//! int socketpair(int domain, int type, int protocol, int sv[2]);
//! ```
//!
//! # POSIX reference
//!
//! POSIX.1-2024 §socketpair — `<sys/socket.h>`.
//!
//! # References
//!
//! - Linux: `net/socket.c` `__sys_socketpair()`
//! - `socketpair(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Socket type and domain constants
// ---------------------------------------------------------------------------

/// Stream socket.
pub const SOCK_STREAM: i32 = 1;
/// Datagram socket.
pub const SOCK_DGRAM: i32 = 2;
/// Sequenced-packet socket.
pub const SOCK_SEQPACKET: i32 = 5;
/// Close-on-exec flag.
pub const SOCK_CLOEXEC: i32 = 0x0008_0000;
/// Non-blocking flag.
pub const SOCK_NONBLOCK: i32 = 0x0000_0800;

/// Mask of flag bits (not part of the socket type).
const SOCK_FLAGS_MASK: i32 = SOCK_CLOEXEC | SOCK_NONBLOCK;

/// Unix domain sockets (the primary `socketpair` domain).
pub const AF_UNIX: i32 = 1;
/// IPv4.
pub const AF_INET: i32 = 2;

/// Default protocol (kernel selects).
pub const PROTO_DEFAULT: i32 = 0;

// ---------------------------------------------------------------------------
// SocketPairArgs — validated arguments
// ---------------------------------------------------------------------------

/// Validated arguments for `socketpair`.
#[derive(Debug, Clone, Copy)]
pub struct SocketPairArgs {
    /// Address family.
    pub domain: i32,
    /// Base socket type (without flags).
    pub sock_type: i32,
    /// Protocol number.
    pub protocol: i32,
    /// Close-on-exec.
    pub cloexec: bool,
    /// Non-blocking.
    pub nonblock: bool,
}

// ---------------------------------------------------------------------------
// SocketPairDescriptor — a single end of the pair
// ---------------------------------------------------------------------------

/// One endpoint of a `socketpair`.
#[derive(Debug, Clone, Copy)]
pub struct SocketPairDescriptor {
    /// File descriptor number.
    pub fd: i32,
    /// Validated creation arguments.
    pub args: SocketPairArgs,
    /// Whether the other end has been closed (peer closed).
    pub peer_closed: bool,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate domain is supported for `socketpair`.
fn validate_domain(domain: i32) -> Result<()> {
    match domain {
        AF_UNIX | AF_INET => Ok(()),
        _ => Err(Error::InvalidArgument),
    }
}

/// Validate socket type for `socketpair`.
///
/// Only stream, datagram, and sequenced-packet sockets are supported.
fn validate_type(type_raw: i32) -> Result<i32> {
    let base = type_raw & !SOCK_FLAGS_MASK;
    match base {
        SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET => Ok(base),
        _ => Err(Error::InvalidArgument),
    }
}

/// Validate and parse `socketpair` arguments.
///
/// # Errors
///
/// [`Error::InvalidArgument`] for unsupported domain, type, or unknown flags.
pub fn validate_socketpair(domain: i32, type_raw: i32, protocol: i32) -> Result<SocketPairArgs> {
    validate_domain(domain)?;
    let sock_type = validate_type(type_raw)?;
    // For AF_UNIX, protocol must be 0.
    if domain == AF_UNIX && protocol != PROTO_DEFAULT {
        return Err(Error::InvalidArgument);
    }
    Ok(SocketPairArgs {
        domain,
        sock_type,
        protocol,
        cloexec: type_raw & SOCK_CLOEXEC != 0,
        nonblock: type_raw & SOCK_NONBLOCK != 0,
    })
}

// ---------------------------------------------------------------------------
// SocketPairTable — tracks open socket pairs
// ---------------------------------------------------------------------------

/// Maximum socket pairs tracked.
const MAX_PAIRS: usize = 64;

/// A connected socket pair.
#[derive(Clone, Copy)]
struct PairRecord {
    fd0: i32,
    fd1: i32,
    args: SocketPairArgs,
    active: bool,
}

/// Table of open socket pairs.
pub struct SocketPairTable {
    pairs: [PairRecord; MAX_PAIRS],
    next_fd: i32,
}

impl SocketPairTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            pairs: [const {
                PairRecord {
                    fd0: 0,
                    fd1: 0,
                    args: SocketPairArgs {
                        domain: AF_UNIX,
                        sock_type: SOCK_STREAM,
                        protocol: 0,
                        cloexec: false,
                        nonblock: false,
                    },
                    active: false,
                }
            }; MAX_PAIRS],
            next_fd: 3,
        }
    }

    /// Allocate a connected socket pair.
    ///
    /// Returns `(fd0, fd1)`.
    pub fn allocate(&mut self, args: SocketPairArgs) -> Result<(i32, i32)> {
        let slot = self
            .pairs
            .iter()
            .position(|p| !p.active)
            .ok_or(Error::OutOfMemory)?;
        let fd0 = self.next_fd;
        self.next_fd = self.next_fd.saturating_add(1);
        let fd1 = self.next_fd;
        self.next_fd = self.next_fd.saturating_add(1);
        self.pairs[slot] = PairRecord {
            fd0,
            fd1,
            args,
            active: true,
        };
        Ok((fd0, fd1))
    }

    /// Check if `fd` belongs to an active socket pair.
    pub fn is_socket_fd(&self, fd: i32) -> bool {
        self.pairs
            .iter()
            .any(|p| p.active && (p.fd0 == fd || p.fd1 == fd))
    }

    /// Return the peer fd for `fd`.
    pub fn peer_fd(&self, fd: i32) -> Option<i32> {
        self.pairs
            .iter()
            .find(|p| p.active && (p.fd0 == fd || p.fd1 == fd))
            .map(|p| if p.fd0 == fd { p.fd1 } else { p.fd0 })
    }

    /// Close an fd (marks the pair half as gone; full pair removed when both closed).
    pub fn close(&mut self, fd: i32) -> bool {
        for pair in &mut self.pairs {
            if pair.active && (pair.fd0 == fd || pair.fd1 == fd) {
                pair.active = false;
                return true;
            }
        }
        false
    }
}

impl Default for SocketPairTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// sys_socketpair — entry point
// ---------------------------------------------------------------------------

/// Handler for `socketpair(2)`.
///
/// Validates arguments and allocates a connected socket pair.
///
/// # Returns
///
/// `Ok((fd0, fd1))` — the two file descriptors.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — bad domain, type, or protocol.
/// * [`Error::OutOfMemory`]     — pair table full.
pub fn sys_socketpair(
    table: &mut SocketPairTable,
    domain: i32,
    type_raw: i32,
    protocol: i32,
) -> Result<(i32, i32)> {
    let args = validate_socketpair(domain, type_raw, protocol)?;
    table.allocate(args)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_unix_stream_pair() {
        let mut t = SocketPairTable::new();
        let (fd0, fd1) = sys_socketpair(&mut t, AF_UNIX, SOCK_STREAM, 0).unwrap();
        assert_ne!(fd0, fd1);
        assert!(t.is_socket_fd(fd0));
        assert!(t.is_socket_fd(fd1));
    }

    #[test]
    fn peer_fd_lookup() {
        let mut t = SocketPairTable::new();
        let (fd0, fd1) = sys_socketpair(&mut t, AF_UNIX, SOCK_DGRAM, 0).unwrap();
        assert_eq!(t.peer_fd(fd0), Some(fd1));
        assert_eq!(t.peer_fd(fd1), Some(fd0));
    }

    #[test]
    fn cloexec_flag() {
        let mut t = SocketPairTable::new();
        let args = validate_socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0).unwrap();
        assert!(args.cloexec);
        t.allocate(args).unwrap();
    }

    #[test]
    fn nonblock_flag() {
        let args = validate_socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0).unwrap();
        assert!(args.nonblock);
    }

    #[test]
    fn bad_domain_rejected() {
        let mut t = SocketPairTable::new();
        assert_eq!(
            sys_socketpair(&mut t, 99, SOCK_STREAM, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unix_nonzero_protocol_rejected() {
        let mut t = SocketPairTable::new();
        assert_eq!(
            sys_socketpair(&mut t, AF_UNIX, SOCK_STREAM, 6),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn bad_type_rejected() {
        let mut t = SocketPairTable::new();
        assert_eq!(
            sys_socketpair(&mut t, AF_UNIX, 99, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn close_socket() {
        let mut t = SocketPairTable::new();
        let (fd0, _) = sys_socketpair(&mut t, AF_UNIX, SOCK_STREAM, 0).unwrap();
        assert!(t.close(fd0));
        assert!(!t.is_socket_fd(fd0));
    }
}
