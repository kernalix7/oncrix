// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `socketpair` syscall handler.
//!
//! Implements `socketpair(2)` per POSIX.1-2024.
//! `socketpair` creates two connected, unnamed sockets and returns
//! a pair of file descriptors referring to them.
//!
//! # References
//!
//! - POSIX.1-2024: `socketpair()`
//! - Linux man pages: `socketpair(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Address family constants
// ---------------------------------------------------------------------------

/// Unspecified address family.
pub const AF_UNSPEC: i32 = 0;
/// Unix domain sockets (local communication).
pub const AF_UNIX: i32 = 1;
/// Alias for `AF_UNIX`.
pub const AF_LOCAL: i32 = 1;
/// IPv4 Internet protocols.
pub const AF_INET: i32 = 2;
/// IPv6 Internet protocols.
pub const AF_INET6: i32 = 10;

// ---------------------------------------------------------------------------
// Socket type constants
// ---------------------------------------------------------------------------

/// Sequenced, reliable, two-way byte-stream socket.
pub const SOCK_STREAM: i32 = 1;
/// Connectionless, unreliable datagrams.
pub const SOCK_DGRAM: i32 = 2;
/// Sequenced, reliable datagrams.
pub const SOCK_SEQPACKET: i32 = 5;

/// Mask covering the base socket type bits (low 4 bits).
const SOCK_TYPE_MASK: i32 = 0xF;

/// Set non-blocking mode on the new socket file descriptors.
pub const SOCK_NONBLOCK: i32 = 0x800;
/// Set close-on-exec on the new socket file descriptors.
pub const SOCK_CLOEXEC: i32 = 0x80000;

/// Mask of valid flag bits that may be OR'd with the socket type.
const SOCK_FLAGS_VALID: i32 = SOCK_NONBLOCK | SOCK_CLOEXEC;

// ---------------------------------------------------------------------------
// SocketPairFlags — decoded from the type+flags argument
// ---------------------------------------------------------------------------

/// Decoded flags from the `sock_type` argument to `socketpair`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SocketPairFlags {
    /// Whether SOCK_NONBLOCK was set.
    pub nonblock: bool,
    /// Whether SOCK_CLOEXEC was set.
    pub cloexec: bool,
}

impl SocketPairFlags {
    /// Decode flags from a combined `type | flags` value.
    pub const fn from_type_flags(type_flags: i32) -> Self {
        let nonblock = type_flags & SOCK_NONBLOCK != 0;
        let cloexec = type_flags & SOCK_CLOEXEC != 0;
        Self { nonblock, cloexec }
    }
}

// ---------------------------------------------------------------------------
// SocketPairArgs — bundled arguments
// ---------------------------------------------------------------------------

/// Arguments for the `socketpair` syscall.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SocketPairArgs {
    /// Communication domain (AF_UNIX, AF_INET, etc.).
    pub domain: i32,
    /// Socket type with optional flags OR'd in (SOCK_STREAM | SOCK_NONBLOCK, etc.).
    pub sock_type: i32,
    /// Protocol (0 = auto-select).
    pub protocol: i32,
}

impl SocketPairArgs {
    /// Validate the `socketpair` arguments.
    ///
    /// Returns `Err(InvalidArgument)` when:
    /// - `domain` is not a recognised address family.
    /// - The base socket type is not STREAM, DGRAM, or SEQPACKET.
    /// - `sock_type` contains unknown flag bits.
    /// - `AF_UNIX` is not used (currently the only fully supported domain).
    pub fn validate(&self) -> Result<()> {
        validate_domain(self.domain)?;
        let base = self.sock_type & SOCK_TYPE_MASK;
        validate_base_type(base)?;
        let extra_flags = self.sock_type & !SOCK_TYPE_MASK;
        if extra_flags & !SOCK_FLAGS_VALID != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Return the decoded socket flags.
    pub fn flags(&self) -> SocketPairFlags {
        SocketPairFlags::from_type_flags(self.sock_type)
    }

    /// Return the base socket type (without flags).
    pub fn base_type(&self) -> i32 {
        self.sock_type & SOCK_TYPE_MASK
    }
}

// ---------------------------------------------------------------------------
// SocketPairResult — newly created fd pair
// ---------------------------------------------------------------------------

/// File descriptor pair returned by `socketpair`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SocketPairResult {
    /// First file descriptor (read end or full-duplex end 0).
    pub fd0: i32,
    /// Second file descriptor (write end or full-duplex end 1).
    pub fd1: i32,
}

// ---------------------------------------------------------------------------
// FdAllocator — simulated file descriptor allocator
// ---------------------------------------------------------------------------

/// Simulated file descriptor allocator for testing.
///
/// A production implementation allocates from the process file descriptor table.
#[derive(Debug)]
pub struct FdAllocator {
    next_fd: i32,
}

impl FdAllocator {
    /// Create a new allocator starting at the given fd number.
    pub fn new(start: i32) -> Self {
        Self { next_fd: start }
    }

    /// Allocate the next available file descriptor.
    pub fn alloc(&mut self) -> Result<i32> {
        if self.next_fd >= 1024 {
            return Err(Error::OutOfMemory);
        }
        let fd = self.next_fd;
        self.next_fd += 1;
        Ok(fd)
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate the address family for `socketpair`.
fn validate_domain(domain: i32) -> Result<()> {
    match domain {
        AF_UNIX | AF_INET | AF_INET6 => Ok(()),
        _ => Err(Error::InvalidArgument),
    }
}

/// Validate the base socket type (without flag bits).
fn validate_base_type(base: i32) -> Result<()> {
    match base {
        SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET => Ok(()),
        _ => Err(Error::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// Public syscall handlers
// ---------------------------------------------------------------------------

/// `socketpair` — create a pair of connected sockets.
///
/// Creates two sockets of the specified `domain` and `sock_type` that are
/// connected to each other. Data written to `fd0` may be read from `fd1`
/// and vice versa. Both fds inherit `SOCK_NONBLOCK` and `SOCK_CLOEXEC`
/// flags if set in `sock_type`.
///
/// Currently only `AF_UNIX` sockets are fully supported. Other domains
/// return `Err(NotImplemented)`.
///
/// Returns `(fd0, fd1)` on success.
///
/// # Errors
///
/// | `Error`           | Condition                                     |
/// |-------------------|-----------------------------------------------|
/// | `InvalidArgument` | Unknown domain, type, or flag bits            |
/// | `NotImplemented`  | Non-`AF_UNIX` domain (not yet supported)      |
/// | `OutOfMemory`     | File descriptor table is full                 |
///
/// Reference: POSIX.1-2024 §socketpair.
pub fn do_socketpair(
    domain: i32,
    sock_type: i32,
    protocol: i32,
    fd_alloc: &mut FdAllocator,
) -> Result<SocketPairResult> {
    let args = SocketPairArgs {
        domain,
        sock_type,
        protocol,
    };
    args.validate()?;

    // Only AF_UNIX sockets are currently supported.
    if domain != AF_UNIX && domain != AF_LOCAL {
        return Err(Error::NotImplemented);
    }

    let _ = args.flags();
    let _ = protocol;

    // Allocate two file descriptors.
    let fd0 = fd_alloc.alloc()?;
    let fd1 = fd_alloc.alloc()?;

    // Stub: real implementation creates a socket pair backed by an
    // in-kernel pipe or socket object and wires them together.
    Ok(SocketPairResult { fd0, fd1 })
}

/// Validate `socketpair` arguments without creating descriptors.
pub fn validate_socketpair_args(domain: i32, sock_type: i32) -> Result<()> {
    let args = SocketPairArgs {
        domain,
        sock_type,
        protocol: 0,
    };
    args.validate()
}
