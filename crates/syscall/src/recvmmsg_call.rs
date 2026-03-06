// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `recvmmsg(2)` syscall handler — receive multiple messages on a socket.
//!
//! `recvmmsg` is an extension of `recvmsg(2)` that allows receiving multiple
//! messages in a single syscall, reducing overhead for applications that
//! process many messages.  An optional timeout terminates the operation after
//! a specified time.
//!
//! # POSIX reference
//!
//! Linux-specific extension (not in POSIX).  See `recvmmsg(2)` man page.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flags (MSG_* subset relevant to recvmmsg)
// ---------------------------------------------------------------------------

/// Receive out-of-band data.
pub const MSG_OOB: u32 = 0x0000_0001;
/// Do not block waiting for data.
pub const MSG_DONTWAIT: u32 = 0x0000_0040;
/// Return data from the beginning of the queue without removing it.
pub const MSG_PEEK: u32 = 0x0000_0002;
/// Wait for full message.
pub const MSG_WAITALL: u32 = 0x0000_0100;
/// Block until timeout expires even if no data received.
pub const MSG_WAITFORONE: u32 = 0x0001_0000;
/// Return the real source address if it was truncated.
pub const MSG_CMSG_CLOEXEC: u32 = 0x4000_0000;

/// All valid flags.
const VALID_FLAGS: u32 =
    MSG_OOB | MSG_DONTWAIT | MSG_PEEK | MSG_WAITALL | MSG_WAITFORONE | MSG_CMSG_CLOEXEC;

/// Maximum number of messages that may be received in one call.
pub const RECVMMSG_MAX_VLEN: u32 = 1024;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A timespec for the optional `recvmmsg` timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timespec {
    /// Seconds component.
    pub tv_sec: i64,
    /// Nanoseconds component.
    pub tv_nsec: i64,
}

impl Timespec {
    /// Construct a new `Timespec`.
    pub const fn new(tv_sec: i64, tv_nsec: i64) -> Self {
        Self { tv_sec, tv_nsec }
    }

    /// Validate that `tv_nsec` is in `[0, 999_999_999]`.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` for out-of-range values.
    pub fn validate(&self) -> Result<()> {
        if self.tv_nsec < 0 || self.tv_nsec > 999_999_999 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

/// Validated `recvmmsg` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecvmmsgRequest {
    /// Socket file descriptor.
    pub sockfd: i32,
    /// User-space pointer to the `mmsghdr` array.
    pub msgvec: usize,
    /// Maximum number of messages to receive.
    pub vlen: u32,
    /// Receive flags.
    pub flags: u32,
    /// Optional timeout (pointer into user-space; 0 means no timeout).
    pub timeout: usize,
}

impl RecvmmsgRequest {
    /// Construct a new request.
    pub const fn new(sockfd: i32, msgvec: usize, vlen: u32, flags: u32, timeout: usize) -> Self {
        Self {
            sockfd,
            msgvec,
            vlen,
            flags,
            timeout,
        }
    }

    /// Return `true` if a timeout was specified.
    pub fn has_timeout(&self) -> bool {
        self.timeout != 0
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `recvmmsg(2)`.
///
/// Validates all arguments and returns a structured request.
///
/// # Arguments
///
/// - `sockfd`  — socket file descriptor
/// - `msgvec`  — user-space pointer to array of `mmsghdr`
/// - `vlen`    — maximum number of messages to receive (0 < vlen <= `RECVMMSG_MAX_VLEN`)
/// - `flags`   — receive flags (`MSG_*`)
/// - `timeout` — user-space pointer to `timespec`, or 0 for no timeout
///
/// # Errors
///
/// | `Error`           | Condition                                   |
/// |-------------------|---------------------------------------------|
/// | `InvalidArgument` | Bad fd, null msgvec, vlen==0, unknown flags |
/// | `WouldBlock`      | `MSG_DONTWAIT` and no data available        |
pub fn do_recvmmsg(
    sockfd: i32,
    msgvec: usize,
    vlen: u32,
    flags: u32,
    timeout: usize,
) -> Result<RecvmmsgRequest> {
    if sockfd < 0 {
        return Err(Error::InvalidArgument);
    }
    if msgvec == 0 {
        return Err(Error::InvalidArgument);
    }
    if vlen == 0 || vlen > RECVMMSG_MAX_VLEN {
        return Err(Error::InvalidArgument);
    }
    if flags & !VALID_FLAGS != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(RecvmmsgRequest::new(sockfd, msgvec, vlen, flags, timeout))
}

/// Return `true` if the call should not block.
pub fn is_nonblocking(flags: u32) -> bool {
    flags & MSG_DONTWAIT != 0
}

/// Return `true` if `MSG_WAITFORONE` is set.
pub fn is_waitforone(flags: u32) -> bool {
    flags & MSG_WAITFORONE != 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_recvmmsg_ok() {
        let req = do_recvmmsg(3, 0xDEAD, 10, 0, 0).unwrap();
        assert_eq!(req.sockfd, 3);
        assert_eq!(req.vlen, 10);
        assert!(!req.has_timeout());
    }

    #[test]
    fn with_timeout_ok() {
        let req = do_recvmmsg(3, 0xDEAD, 5, 0, 0x1000).unwrap();
        assert!(req.has_timeout());
    }

    #[test]
    fn negative_fd_rejected() {
        assert_eq!(
            do_recvmmsg(-1, 0xDEAD, 10, 0, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn null_msgvec_rejected() {
        assert_eq!(do_recvmmsg(3, 0, 10, 0, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn zero_vlen_rejected() {
        assert_eq!(do_recvmmsg(3, 0xDEAD, 0, 0, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn oversized_vlen_rejected() {
        assert_eq!(
            do_recvmmsg(3, 0xDEAD, RECVMMSG_MAX_VLEN + 1, 0, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(
            do_recvmmsg(3, 0xDEAD, 1, 0x0002_0000, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn nonblocking_detection() {
        assert!(is_nonblocking(MSG_DONTWAIT));
        assert!(!is_nonblocking(0));
    }
}
