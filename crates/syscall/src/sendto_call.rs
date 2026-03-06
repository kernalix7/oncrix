// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `sendto` / `send` syscall handlers.
//!
//! Implements `sendto(2)` and `send(2)` per POSIX.1-2024.
//! `sendto` writes a message to a socket, optionally specifying the
//! destination address (required for connectionless sockets like UDP).
//!
//! # References
//!
//! - POSIX.1-2024: `sendto()`
//! - Linux man pages: `sendto(2)`, `send(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Message flags (MSG_*)
// ---------------------------------------------------------------------------

/// Do not generate SIGPIPE on a broken connection.
pub const MSG_NOSIGNAL: i32 = 0x4000;
/// Hint that more data will follow immediately (TCP_CORK equivalent).
pub const MSG_MORE: i32 = 0x8000;
/// Send out-of-band data.
pub const MSG_OOB: i32 = 0x0001;
/// Non-blocking send (return immediately if send buffer is full).
pub const MSG_DONTWAIT: i32 = 0x0040;
/// Do not route (bypass routing table).
pub const MSG_DONTROUTE: i32 = 0x0004;
/// End of record (SOCK_SEQPACKET only).
pub const MSG_EOR: i32 = 0x0080;

/// Mask of flags accepted by `sendto`.
const MSG_SEND_VALID: i32 =
    MSG_NOSIGNAL | MSG_MORE | MSG_OOB | MSG_DONTWAIT | MSG_DONTROUTE | MSG_EOR;

// ---------------------------------------------------------------------------
// Maximum sizes
// ---------------------------------------------------------------------------

/// Maximum single-call send length (256 MiB).
const SEND_MAX_LEN: usize = 256 * 1024 * 1024;

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
// SendToArgs — bundled arguments
// ---------------------------------------------------------------------------

/// Arguments for `sendto` as passed from the syscall dispatcher.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SendToArgs {
    /// Socket file descriptor.
    pub sockfd: i32,
    /// Send flags (`MSG_*` bitmask).
    pub flags: i32,
    /// Data length.
    pub buf_len: usize,
    /// Whether a destination address was supplied.
    pub has_dest: bool,
}

impl SendToArgs {
    /// Validate the send arguments.
    ///
    /// Returns `Err(InvalidArgument)` when:
    /// - `sockfd` is negative.
    /// - `buf_len` exceeds `SEND_MAX_LEN`.
    /// - `flags` contains unrecognised bits.
    pub fn validate(&self) -> Result<()> {
        if self.sockfd < 0 {
            return Err(Error::InvalidArgument);
        }
        if self.buf_len > SEND_MAX_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.flags & !MSG_SEND_VALID != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Return `true` if the non-blocking flag is set.
    pub const fn is_nonblocking(&self) -> bool {
        self.flags & MSG_DONTWAIT != 0
    }

    /// Return `true` if MSG_MORE is set (more data will follow).
    pub const fn is_more(&self) -> bool {
        self.flags & MSG_MORE != 0
    }

    /// Return `true` if out-of-band data should be sent.
    pub const fn is_oob(&self) -> bool {
        self.flags & MSG_OOB != 0
    }
}

// ---------------------------------------------------------------------------
// SendResult — outcome of a send operation
// ---------------------------------------------------------------------------

/// Result of a `sendto` / `send` operation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SendResult {
    /// Number of bytes actually queued into the send buffer.
    pub bytes_sent: usize,
}

// ---------------------------------------------------------------------------
// SocketSendBuffer — simulated send buffer
// ---------------------------------------------------------------------------

/// Simulated socket send buffer capacity tracker.
///
/// A production implementation reaches into the kernel socket object.
#[derive(Debug)]
pub struct SocketSendBuffer {
    /// Remaining capacity in the send buffer.
    capacity: usize,
}

impl SocketSendBuffer {
    /// Create a new simulated send buffer with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self { capacity }
    }

    /// Try to enqueue `data` (or up to `capacity` bytes).
    ///
    /// Returns the number of bytes accepted.
    pub fn enqueue(&mut self, data: &[u8]) -> usize {
        let can_send = data.len().min(self.capacity);
        self.capacity -= can_send;
        can_send
    }

    /// Return the remaining space in the buffer.
    pub fn free_space(&self) -> usize {
        self.capacity
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
    if flags & !MSG_SEND_VALID != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public syscall handlers
// ---------------------------------------------------------------------------

/// `sendto` — send a message to a socket, with optional destination address.
///
/// Writes `buf` to the socket identified by `sockfd`. For connectionless
/// sockets (e.g. UDP), `dest` specifies the target address. For connected
/// sockets, `dest` must be `None`.
///
/// When `MSG_DONTWAIT` is set, the call returns `Err(WouldBlock)` instead
/// of blocking if the send buffer is full.
///
/// Returns the number of bytes sent.
///
/// # Errors
///
/// | `Error`           | Condition                                        |
/// |-------------------|--------------------------------------------------|
/// | `InvalidArgument` | `sockfd < 0`, unknown flags, or `buf` too large  |
/// | `WouldBlock`      | Non-blocking and send buffer full                |
///
/// Reference: POSIX.1-2024 §sendto.
pub fn do_sendto(
    sockfd: i32,
    buf: &[u8],
    flags: i32,
    dest: Option<&SockaddrStorage>,
    send_buf: Option<&mut SocketSendBuffer>,
) -> Result<usize> {
    validate_fd(sockfd)?;
    validate_flags(flags)?;

    if buf.len() > SEND_MAX_LEN {
        return Err(Error::InvalidArgument);
    }

    // dest accepted for routing; production code would validate the family
    // against the socket type.
    let _ = dest;

    let is_nonblocking = flags & MSG_DONTWAIT != 0;

    match send_buf {
        None => {
            if is_nonblocking {
                return Err(Error::WouldBlock);
            }
            Err(Error::NotImplemented)
        }
        Some(sbuf) => {
            if sbuf.free_space() == 0 {
                if is_nonblocking {
                    return Err(Error::WouldBlock);
                }
                return Err(Error::NotImplemented);
            }
            let sent = sbuf.enqueue(buf);
            Ok(sent)
        }
    }
}

/// `send` — send a message on a connected socket.
///
/// Equivalent to `sendto` with `dest = None`.
pub fn do_send(
    sockfd: i32,
    buf: &[u8],
    flags: i32,
    send_buf: Option<&mut SocketSendBuffer>,
) -> Result<usize> {
    do_sendto(sockfd, buf, flags, None, send_buf)
}

/// Validate `sendto` arguments without performing the send.
pub fn validate_sendto_args(sockfd: i32, buf_len: usize, flags: i32) -> Result<()> {
    validate_fd(sockfd)?;
    validate_flags(flags)?;
    if buf_len > SEND_MAX_LEN {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}
