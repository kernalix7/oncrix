// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `recvfrom(2)` / `recvmsg(2)` — socket receive dispatch and validation.
//!
//! Provides flag validation, message header validation, and control-message
//! (ancillary data) parsing shared by socket receive operations.
//!
//! # Syscall signatures
//!
//! ```text
//! ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
//!                  struct sockaddr *src_addr, socklen_t *addrlen);
//! ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
//! ```
//!
//! # POSIX reference
//!
//! POSIX.1-2024 §recvfrom, §recvmsg — `<sys/socket.h>`.
//!
//! # References
//!
//! - Linux: `net/socket.c` `__sys_recvmsg()`
//! - `recvmsg(2)`, `recvfrom(2)` man pages
//! - `cmsg(3)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Receive flag constants
// ---------------------------------------------------------------------------

/// Do not block.
pub const MSG_DONTWAIT: i32 = 0x40;
/// Wait for full buffer.
pub const MSG_WAITALL: i32 = 0x100;
/// Receive out-of-band data.
pub const MSG_OOB: i32 = 0x1;
/// Peek at data (don't remove from queue).
pub const MSG_PEEK: i32 = 0x2;
/// Truncate message (report original length).
pub const MSG_TRUNC: i32 = 0x20;
/// Control data was truncated.
pub const MSG_CTRUNC: i32 = 0x8;
/// Block until at least one message arrives.
pub const MSG_WAITFORONE: i32 = 0x1_0000;
/// Use receiver credentials.
pub const MSG_CMSG_CLOEXEC: i32 = 0x40_000_000;

/// Mask of flags the user may pass to recv*.
const MSG_RECV_FLAGS_KNOWN: i32 = MSG_DONTWAIT
    | MSG_WAITALL
    | MSG_OOB
    | MSG_PEEK
    | MSG_TRUNC
    | MSG_CTRUNC
    | MSG_WAITFORONE
    | MSG_CMSG_CLOEXEC;

// ---------------------------------------------------------------------------
// Control message levels and types
// ---------------------------------------------------------------------------

/// Socket-level control message.
pub const SOL_SOCKET: i32 = 1;
/// File descriptor passing.
pub const SCM_RIGHTS: i32 = 1;
/// Credentials.
pub const SCM_CREDENTIALS: i32 = 2;
/// Packet info (IP_PKTINFO equivalent for generic sockets).
pub const SCM_TIMESTAMP: i32 = 29;

// ---------------------------------------------------------------------------
// RecvFlags — validated receive flags
// ---------------------------------------------------------------------------

/// Validated receive flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RecvFlags {
    /// Do not block.
    pub dontwait: bool,
    /// Wait for full buffer.
    pub waitall: bool,
    /// Receive OOB data.
    pub oob: bool,
    /// Peek (don't consume).
    pub peek: bool,
    /// Close-on-exec for received fds.
    pub cmsg_cloexec: bool,
}

impl RecvFlags {
    /// Parse and validate receive flags.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] for unknown bits.
    pub fn from_raw(raw: i32) -> Result<Self> {
        if raw & !MSG_RECV_FLAGS_KNOWN != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            dontwait: raw & MSG_DONTWAIT != 0,
            waitall: raw & MSG_WAITALL != 0,
            oob: raw & MSG_OOB != 0,
            peek: raw & MSG_PEEK != 0,
            cmsg_cloexec: raw & MSG_CMSG_CLOEXEC != 0,
        })
    }
}

// ---------------------------------------------------------------------------
// CmsgHeader — control message header
// ---------------------------------------------------------------------------

/// Control message header (`struct cmsghdr`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CmsgHeader {
    /// Total length including data.
    pub cmsg_len: usize,
    /// Originating protocol.
    pub cmsg_level: i32,
    /// Protocol-specific type.
    pub cmsg_type: i32,
}

impl CmsgHeader {
    /// Minimum valid cmsg header size.
    pub const MIN_SIZE: usize = core::mem::size_of::<Self>();

    /// Validate the header.
    pub fn validate(&self) -> Result<()> {
        if self.cmsg_len < Self::MIN_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Return the data length (total - header size).
    pub const fn data_len(&self) -> usize {
        self.cmsg_len.saturating_sub(Self::MIN_SIZE)
    }
}

// ---------------------------------------------------------------------------
// ScmRightsData — file descriptors received via SCM_RIGHTS
// ---------------------------------------------------------------------------

/// Maximum file descriptors per SCM_RIGHTS message.
const SCM_MAX_FDS: usize = 253;

/// Received file descriptors.
pub struct ScmRightsData {
    fds: [i32; SCM_MAX_FDS],
    count: usize,
}

impl ScmRightsData {
    /// Create an empty container.
    pub const fn new() -> Self {
        Self {
            fds: [0; SCM_MAX_FDS],
            count: 0,
        }
    }

    /// Add a file descriptor.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfMemory`] if the limit is reached.
    pub fn push(&mut self, fd: i32) -> Result<()> {
        if self.count >= SCM_MAX_FDS {
            return Err(Error::OutOfMemory);
        }
        self.fds[self.count] = fd;
        self.count += 1;
        Ok(())
    }

    /// Return the slice of received fds.
    pub fn as_slice(&self) -> &[i32] {
        &self.fds[..self.count]
    }
}

impl Default for ScmRightsData {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RecvResult — result of a receive operation
// ---------------------------------------------------------------------------

/// Result of a successful receive operation.
#[derive(Debug, Clone, Copy)]
pub struct RecvResult {
    /// Bytes received.
    pub bytes_received: usize,
    /// Whether the message was truncated.
    pub truncated: bool,
    /// Whether control data was truncated.
    pub ctrl_truncated: bool,
}

// ---------------------------------------------------------------------------
// validate_recv_args — common validation
// ---------------------------------------------------------------------------

/// Validate common arguments to `recvfrom`/`recvmsg`.
///
/// # Arguments
///
/// * `sockfd`  — File descriptor (must be non-negative).
/// * `buflen`  — Receive buffer length.
/// * `flags`   — Message flags.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — negative fd, zero-length buffer, or
///   unknown flags.
pub fn validate_recv_args(sockfd: i32, buflen: usize, flags: i32) -> Result<RecvFlags> {
    if sockfd < 0 {
        return Err(Error::InvalidArgument);
    }
    if buflen == 0 {
        return Err(Error::InvalidArgument);
    }
    RecvFlags::from_raw(flags)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_flags() {
        let f = RecvFlags::from_raw(MSG_DONTWAIT | MSG_PEEK).unwrap();
        assert!(f.dontwait);
        assert!(f.peek);
        assert!(!f.oob);
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(
            RecvFlags::from_raw(0x0100_0000),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn cmsg_header_validate() {
        let h = CmsgHeader {
            cmsg_len: CmsgHeader::MIN_SIZE + 4,
            cmsg_level: SOL_SOCKET,
            cmsg_type: SCM_RIGHTS,
        };
        assert!(h.validate().is_ok());
        assert_eq!(h.data_len(), 4);
    }

    #[test]
    fn cmsg_too_small() {
        let h = CmsgHeader {
            cmsg_len: 0,
            cmsg_level: SOL_SOCKET,
            cmsg_type: SCM_RIGHTS,
        };
        assert_eq!(h.validate(), Err(Error::InvalidArgument));
    }

    #[test]
    fn validate_recv_args_ok() {
        let flags = validate_recv_args(3, 1024, MSG_DONTWAIT).unwrap();
        assert!(flags.dontwait);
    }

    #[test]
    fn validate_recv_args_bad_fd() {
        assert_eq!(validate_recv_args(-1, 1024, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn validate_recv_args_zero_buf() {
        assert_eq!(validate_recv_args(3, 0, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn scm_rights_add_fds() {
        let mut rights = ScmRightsData::new();
        rights.push(5).unwrap();
        rights.push(6).unwrap();
        assert_eq!(rights.as_slice(), &[5, 6]);
    }
}
