// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `recvfrom` / `recv` syscall handlers.
//!
//! Implements `recvfrom(2)` and `recv(2)` per POSIX.1-2024.
//! `recvfrom` reads a message from a socket and optionally fills in
//! the source address of the sender.
//!
//! # References
//!
//! - POSIX.1-2024: `recvfrom()`
//! - Linux man pages: `recvfrom(2)`, `recv(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Message flags (MSG_*)
// ---------------------------------------------------------------------------

/// Do not remove data from the socket buffer (peek only).
pub const MSG_PEEK: i32 = 0x0002;
/// Block until all requested data is received.
pub const MSG_WAITALL: i32 = 0x0100;
/// Non-blocking receive (return immediately if no data).
pub const MSG_DONTWAIT: i32 = 0x0040;
/// Return the real length of the datagram even if truncated.
pub const MSG_TRUNC: i32 = 0x0020;
/// Request out-of-band data.
pub const MSG_OOB: i32 = 0x0001;
/// Do not generate SIGPIPE on broken connection.
pub const MSG_NOSIGNAL: i32 = 0x4000;

/// Mask of flags accepted by `recvfrom`.
const MSG_RECV_VALID: i32 = MSG_PEEK | MSG_WAITALL | MSG_DONTWAIT | MSG_TRUNC | MSG_OOB;

// ---------------------------------------------------------------------------
// Maximum receive sizes
// ---------------------------------------------------------------------------

/// Maximum single-call receive length (256 MiB).
const RECV_MAX_LEN: usize = 256 * 1024 * 1024;

/// Maximum socket address length.
pub const SOCK_ADDR_MAX_LEN: usize = 128;

// ---------------------------------------------------------------------------
// SockaddrStorage — generic address storage
// ---------------------------------------------------------------------------

/// Generic socket address storage large enough to hold any address family.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockaddrStorage {
    /// Address family discriminant.
    pub family: u16,
    /// Opaque address data.
    pub data: [u8; 126],
}

impl Default for SockaddrStorage {
    fn default() -> Self {
        Self {
            family: 0,
            data: [0u8; 126],
        }
    }
}

impl SockaddrStorage {
    /// Construct an unspecified (zeroed) address.
    pub const fn new() -> Self {
        Self {
            family: 0,
            data: [0u8; 126],
        }
    }

    /// Return `true` if this is an unspecified (AF_UNSPEC) address.
    pub const fn is_unspec(&self) -> bool {
        self.family == 0
    }

    /// Return the address family.
    pub const fn family(&self) -> u16 {
        self.family
    }
}

// ---------------------------------------------------------------------------
// RecvFromArgs — bundled arguments
// ---------------------------------------------------------------------------

/// Arguments for `recvfrom` as passed from the syscall dispatcher.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RecvFromArgs {
    /// Socket file descriptor.
    pub sockfd: i32,
    /// Receive flags (`MSG_*` bitmask).
    pub flags: i32,
    /// Expected buffer length (set by caller; actual read may be less).
    pub buf_len: usize,
    /// Whether to fill in the source address (`addr_len > 0`).
    pub want_addr: bool,
}

impl RecvFromArgs {
    /// Validate the arguments.
    ///
    /// Returns `Err(InvalidArgument)` when:
    /// - `sockfd` is negative.
    /// - `buf_len` exceeds `RECV_MAX_LEN`.
    /// - `flags` contains unrecognised bits.
    pub fn validate(&self) -> Result<()> {
        if self.sockfd < 0 {
            return Err(Error::InvalidArgument);
        }
        if self.buf_len > RECV_MAX_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.flags & !MSG_RECV_VALID != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Return `true` if the `MSG_PEEK` flag is set.
    pub const fn is_peek(&self) -> bool {
        self.flags & MSG_PEEK != 0
    }

    /// Return `true` if the `MSG_DONTWAIT` flag is set.
    pub const fn is_nonblocking(&self) -> bool {
        self.flags & MSG_DONTWAIT != 0
    }

    /// Return `true` if `MSG_WAITALL` is set (wait until buffer is full).
    pub const fn is_waitall(&self) -> bool {
        self.flags & MSG_WAITALL != 0
    }

    /// Return `true` if `MSG_TRUNC` is set (report real datagram length).
    pub const fn is_trunc(&self) -> bool {
        self.flags & MSG_TRUNC != 0
    }
}

// ---------------------------------------------------------------------------
// RecvResult — outcome of a receive operation
// ---------------------------------------------------------------------------

/// Result of a `recvfrom` / `recv` operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct RecvResult {
    /// Number of bytes actually placed into the caller's buffer.
    pub bytes_read: usize,
    /// Source address of the sender (present when `want_addr` was set).
    pub src_addr: SockaddrStorage,
    /// Whether the message was truncated (datagram longer than buffer).
    pub truncated: bool,
}

// ---------------------------------------------------------------------------
// SocketBuffer — simulated socket receive buffer
// ---------------------------------------------------------------------------

/// Simulated socket receive buffer for testing purposes.
///
/// A production implementation would reach into the kernel socket object.
#[derive(Debug)]
pub struct SocketBuffer<'a> {
    /// Pending data in the buffer.
    data: &'a [u8],
    /// Sender address associated with the pending datagram.
    peer_addr: SockaddrStorage,
}

impl<'a> SocketBuffer<'a> {
    /// Create a new simulated buffer with `data` from `peer_addr`.
    pub fn new(data: &'a [u8], peer_addr: SockaddrStorage) -> Self {
        Self { data, peer_addr }
    }

    /// Return the number of bytes currently in the buffer.
    pub fn available(&self) -> usize {
        self.data.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Copy up to `buf.len()` bytes from the buffer into `buf`.
    ///
    /// Returns `(bytes_copied, truncated)`.
    pub fn read_into(&self, buf: &mut [u8]) -> (usize, bool) {
        let to_copy = buf.len().min(self.data.len());
        buf[..to_copy].copy_from_slice(&self.data[..to_copy]);
        let truncated = self.data.len() > buf.len();
        (to_copy, truncated)
    }

    /// Return the peer address.
    pub fn peer_addr(&self) -> SockaddrStorage {
        self.peer_addr
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate that the file descriptor is non-negative.
fn validate_fd(fd: i32) -> Result<()> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate the flags field.
fn validate_flags(flags: i32) -> Result<()> {
    if flags & !MSG_RECV_VALID != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public syscall handlers
// ---------------------------------------------------------------------------

/// `recvfrom` — receive a message from a socket, capturing the sender address.
///
/// Reads up to `buf.len()` bytes from the socket identified by `sockfd`.
/// If `want_addr` is `true`, the source address is filled in `RecvResult::src_addr`.
///
/// When `MSG_PEEK` is set the data is not consumed from the socket buffer.
/// When `MSG_DONTWAIT` is set the call returns immediately with
/// `Err(WouldBlock)` if no data is available.
///
/// Returns a `RecvResult` with `bytes_read` set to the number of bytes
/// placed in `buf`.
///
/// # Errors
///
/// | `Error`           | Condition                                         |
/// |-------------------|---------------------------------------------------|
/// | `InvalidArgument` | `sockfd < 0`, unknown flags, or `buf` too large   |
/// | `WouldBlock`      | Non-blocking and no data available                |
///
/// Reference: POSIX.1-2024 §recvfrom.
pub fn do_recvfrom(
    sockfd: i32,
    buf: &mut [u8],
    flags: i32,
    want_addr: bool,
    socket_buf: Option<&SocketBuffer<'_>>,
) -> Result<RecvResult> {
    validate_fd(sockfd)?;
    validate_flags(flags)?;

    if buf.len() > RECV_MAX_LEN {
        return Err(Error::InvalidArgument);
    }

    let is_nonblocking = flags & MSG_DONTWAIT != 0;

    match socket_buf {
        None => {
            if is_nonblocking {
                return Err(Error::WouldBlock);
            }
            Err(Error::NotImplemented)
        }
        Some(sbuf) if sbuf.is_empty() => {
            if is_nonblocking {
                return Err(Error::WouldBlock);
            }
            Err(Error::NotImplemented)
        }
        Some(sbuf) => {
            let (bytes_read, truncated) = sbuf.read_into(buf);
            let src_addr = if want_addr {
                sbuf.peer_addr()
            } else {
                SockaddrStorage::default()
            };
            Ok(RecvResult {
                bytes_read,
                src_addr,
                truncated,
            })
        }
    }
}

/// `recv` — receive a message from a connected socket.
///
/// Equivalent to `recvfrom` with `want_addr = false`.
pub fn do_recv(
    sockfd: i32,
    buf: &mut [u8],
    flags: i32,
    socket_buf: Option<&SocketBuffer<'_>>,
) -> Result<usize> {
    let result = do_recvfrom(sockfd, buf, flags, false, socket_buf)?;
    Ok(result.bytes_read)
}

/// Validate `recvfrom` arguments without performing the receive.
pub fn validate_recvfrom_args(sockfd: i32, buf_len: usize, flags: i32) -> Result<()> {
    validate_fd(sockfd)?;
    validate_flags(flags)?;
    if buf_len > RECV_MAX_LEN {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}
