// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `sendmmsg(2)` syscall handler — send multiple messages on a socket.
//!
//! `sendmmsg` is an extension of `sendmsg(2)` that allows sending multiple
//! messages in a single syscall.  This reduces system call overhead for
//! applications that send many datagrams (e.g., DNS servers, media streaming).
//!
//! # POSIX reference
//!
//! Linux-specific extension (not in POSIX).  See `sendmmsg(2)` man page.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flags (MSG_* subset relevant to sendmmsg)
// ---------------------------------------------------------------------------

/// Send out-of-band data.
pub const MSG_OOB: u32 = 0x0000_0001;
/// Do not use a gateway to send the packet.
pub const MSG_DONTROUTE: u32 = 0x0000_0004;
/// Do not block.
pub const MSG_DONTWAIT: u32 = 0x0000_0040;
/// Close sender side of connection.
pub const MSG_EOR: u32 = 0x0000_0080;
/// Confirm path validity.
pub const MSG_CONFIRM: u32 = 0x0000_0800;
/// Do not generate SIGPIPE.
pub const MSG_NOSIGNAL: u32 = 0x0000_4000;
/// Send more data before completing the datagram.
pub const MSG_MORE: u32 = 0x0000_8000;

/// All valid flags.
const VALID_FLAGS: u32 =
    MSG_OOB | MSG_DONTROUTE | MSG_DONTWAIT | MSG_EOR | MSG_CONFIRM | MSG_NOSIGNAL | MSG_MORE;

/// Maximum number of messages that may be sent in one call.
pub const SENDMMSG_MAX_VLEN: u32 = 1024;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Outcome of a single message in the sendmmsg vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageSendStatus {
    /// The message was sent successfully.
    Sent(u32),
    /// The message failed with an error.
    Failed,
}

impl Default for MessageSendStatus {
    fn default() -> Self {
        Self::Failed
    }
}

/// Validated `sendmmsg` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendmmsgRequest {
    /// Socket file descriptor.
    pub sockfd: i32,
    /// User-space pointer to the `mmsghdr` array.
    pub msgvec: usize,
    /// Number of messages to send.
    pub vlen: u32,
    /// Send flags.
    pub flags: u32,
}

impl SendmmsgRequest {
    /// Construct a new request.
    pub const fn new(sockfd: i32, msgvec: usize, vlen: u32, flags: u32) -> Self {
        Self {
            sockfd,
            msgvec,
            vlen,
            flags,
        }
    }
}

/// Per-message result returned to user-space via the `mmsghdr.msg_len` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MmsgResult {
    /// Number of bytes sent for this message.
    pub bytes_sent: u32,
}

impl MmsgResult {
    /// Construct a new result.
    pub const fn new(bytes_sent: u32) -> Self {
        Self { bytes_sent }
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `sendmmsg(2)`.
///
/// Validates all arguments and returns a structured request.
///
/// # Arguments
///
/// - `sockfd` — socket file descriptor
/// - `msgvec` — user-space pointer to array of `mmsghdr`
/// - `vlen`   — number of messages to send (0 < vlen <= `SENDMMSG_MAX_VLEN`)
/// - `flags`  — send flags (`MSG_*`)
///
/// # Errors
///
/// | `Error`           | Condition                                   |
/// |-------------------|---------------------------------------------|
/// | `InvalidArgument` | Bad fd, null msgvec, vlen==0, unknown flags |
/// | `WouldBlock`      | `MSG_DONTWAIT` and would block              |
pub fn do_sendmmsg(sockfd: i32, msgvec: usize, vlen: u32, flags: u32) -> Result<SendmmsgRequest> {
    if sockfd < 0 {
        return Err(Error::InvalidArgument);
    }
    if msgvec == 0 {
        return Err(Error::InvalidArgument);
    }
    if vlen == 0 || vlen > SENDMMSG_MAX_VLEN {
        return Err(Error::InvalidArgument);
    }
    if flags & !VALID_FLAGS != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(SendmmsgRequest::new(sockfd, msgvec, vlen, flags))
}

/// Return `true` if the call should not block.
pub fn is_nonblocking(flags: u32) -> bool {
    flags & MSG_DONTWAIT != 0
}

/// Return `true` if `MSG_MORE` is set (kernel should coalesce).
pub fn is_more(flags: u32) -> bool {
    flags & MSG_MORE != 0
}

/// Return `true` if `MSG_NOSIGNAL` is set.
pub fn is_nosignal(flags: u32) -> bool {
    flags & MSG_NOSIGNAL != 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_sendmmsg_ok() {
        let req = do_sendmmsg(3, 0xDEAD, 5, 0).unwrap();
        assert_eq!(req.sockfd, 3);
        assert_eq!(req.vlen, 5);
        assert_eq!(req.flags, 0);
    }

    #[test]
    fn negative_fd_rejected() {
        assert_eq!(do_sendmmsg(-1, 0xDEAD, 5, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn null_msgvec_rejected() {
        assert_eq!(do_sendmmsg(3, 0, 5, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn zero_vlen_rejected() {
        assert_eq!(do_sendmmsg(3, 0xDEAD, 0, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn oversized_vlen_rejected() {
        assert_eq!(
            do_sendmmsg(3, 0xDEAD, SENDMMSG_MAX_VLEN + 1, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(
            do_sendmmsg(3, 0xDEAD, 5, 0x0010_0000),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn nonblocking_detection() {
        assert!(is_nonblocking(MSG_DONTWAIT));
        assert!(!is_nonblocking(0));
    }

    #[test]
    fn more_detection() {
        assert!(is_more(MSG_MORE));
        assert!(!is_more(MSG_NOSIGNAL));
    }

    #[test]
    fn nosignal_detection() {
        assert!(is_nosignal(MSG_NOSIGNAL));
        assert!(!is_nosignal(0));
    }
}
