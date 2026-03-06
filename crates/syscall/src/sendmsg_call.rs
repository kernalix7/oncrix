// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `sendmsg(2)` and `recvmsg(2)` syscall handlers.
//!
//! These syscalls provide the most general interface for sending and receiving
//! data over sockets, supporting scatter/gather I/O via `struct iovec`,
//! optional ancillary (control) data, and per-operation flags.
//!
//! `sendmsg` transmits a message to a socket.
//! `recvmsg` receives a message from a socket, and can return ancillary data
//! (e.g., `SCM_RIGHTS` file descriptor passing, `SCM_CREDENTIALS`, timestamps).
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `sendmsg()` and `recvmsg()` specifications.
//!
//! Key behaviours:
//! - Data is described by an array of `iovec` structures (scatter/gather).
//! - The `msg_flags` field of `msghdr` is set by `recvmsg` (output-only).
//! - Ancillary data is exchanged through the `msg_control` / `msg_controllen`
//!   fields using `cmsghdr` chaining.
//! - `MSG_TRUNC` in `recvmsg` flags: data was truncated because the receive
//!   buffer was too small.
//! - `MSG_CTRUNC`: ancillary data was truncated.
//! - `MSG_EOR`: end-of-record marker for `SOCK_SEQPACKET`.
//! - `MSG_DONTWAIT`: non-blocking for this call only.
//! - `MSG_WAITALL`: wait until the receive buffer is fully filled.
//!
//! # References
//!
//! - POSIX.1-2024: `sendmsg()`, `recvmsg()`
//! - Linux man pages: `sendmsg(2)`, `recvmsg(2)`, `cmsg(3)`
//! - Linux source: `net/socket.c` (`__sys_sendmsg`, `__sys_recvmsg`)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants — message flags
// ---------------------------------------------------------------------------

/// Flag: peek at incoming data without removing from queue.
pub const MSG_PEEK: i32 = 0x02;
/// Flag: send/receive out-of-band data.
pub const MSG_OOB: i32 = 0x01;
/// Flag: non-blocking operation for this call only.
pub const MSG_DONTWAIT: i32 = 0x40;
/// Flag: do not route the packet.
pub const MSG_DONTROUTE: i32 = 0x04;
/// Flag: wait for the full request to be satisfied (receive).
pub const MSG_WAITALL: i32 = 0x100;
/// Flag: data was truncated (set by kernel on receive).
pub const MSG_TRUNC: i32 = 0x20;
/// Flag: ancillary data was truncated (set by kernel on receive).
pub const MSG_CTRUNC: i32 = 0x08;
/// Flag: end-of-record marker.
pub const MSG_EOR: i32 = 0x80;
/// Flag: socket error was queued (Linux extension).
pub const MSG_ERRQUEUE: i32 = 0x2000;
/// Flag: use close-on-exec for received file descriptors.
pub const MSG_CMSG_CLOEXEC: i32 = 0x40000000;

/// All valid flags for `sendmsg`.
const SENDMSG_VALID_FLAGS: i32 = MSG_OOB | MSG_DONTROUTE | MSG_DONTWAIT | MSG_EOR | MSG_NOSIGNAL;

/// Flag: do not generate `SIGPIPE` if the peer has closed the connection.
pub const MSG_NOSIGNAL: i32 = 0x4000;

/// All valid flags for `recvmsg`.
const RECVMSG_VALID_FLAGS: i32 =
    MSG_OOB | MSG_PEEK | MSG_WAITALL | MSG_DONTWAIT | MSG_ERRQUEUE | MSG_CMSG_CLOEXEC;

// ---------------------------------------------------------------------------
// Constants — control message (cmsg) types
// ---------------------------------------------------------------------------

/// Socket-level control messages.
pub const SOL_SOCKET: i32 = 1;
/// Ancillary data type: pass file descriptors.
pub const SCM_RIGHTS: i32 = 1;
/// Ancillary data type: pass credentials.
pub const SCM_CREDENTIALS: i32 = 2;
/// Ancillary data type: receive SO_TIMESTAMP.
pub const SCM_TIMESTAMP: i32 = 29;

// ---------------------------------------------------------------------------
// Iovec — scatter/gather descriptor
// ---------------------------------------------------------------------------

/// Scatter/gather I/O vector, mirroring POSIX `struct iovec`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoVec {
    /// Pointer to the data buffer (user address).
    pub base: u64,
    /// Length of the data buffer in bytes.
    pub len: usize,
}

impl IoVec {
    /// Create a new `IoVec` with the given base address and length.
    pub const fn new(base: u64, len: usize) -> Self {
        Self { base, len }
    }

    /// Return the total byte count.
    pub const fn size(&self) -> usize {
        self.len
    }
}

// ---------------------------------------------------------------------------
// Control message header
// ---------------------------------------------------------------------------

/// Control message header (`struct cmsghdr`).
///
/// Ancillary messages are stored in the control buffer as a sequence of
/// `CmsgHdr` records, each with a header followed by the payload.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CmsgHdr {
    /// Total length of this control message (header + data).
    pub cmsg_len: u32,
    /// Originating protocol level.
    pub cmsg_level: i32,
    /// Type of the control message.
    pub cmsg_type: i32,
}

impl CmsgHdr {
    /// Size of the header itself in bytes.
    pub const HEADER_SIZE: usize = core::mem::size_of::<CmsgHdr>();

    /// Return the length of the ancillary data payload (excluding header).
    pub const fn data_len(&self) -> usize {
        if self.cmsg_len as usize >= Self::HEADER_SIZE {
            self.cmsg_len as usize - Self::HEADER_SIZE
        } else {
            0
        }
    }
}

// ---------------------------------------------------------------------------
// Message header
// ---------------------------------------------------------------------------

/// Maximum number of `iovec` entries in a single `sendmsg`/`recvmsg` call.
pub const IOV_MAX: usize = 1024;

/// Maximum ancillary data buffer size.
pub const CMSG_BUF_MAX: usize = 4096;

/// In-kernel representation of POSIX `struct msghdr`.
///
/// The `name` and `control` buffers are described by user-space pointers
/// in the actual system call; here we use lengths and flags for validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsgHdr {
    /// Optional destination (send) or source (receive) address.
    pub name: Option<[u8; 128]>,
    /// Length of the address, if present.
    pub name_len: u32,
    /// Scatter/gather I/O vectors.
    pub iov: [IoVec; 8],
    /// Number of valid entries in `iov`.
    pub iov_count: usize,
    /// Ancillary (control) data buffer.
    pub control: [u8; CMSG_BUF_MAX],
    /// Number of valid bytes in `control`.
    pub control_len: usize,
    /// Message flags (set by kernel on receive; sent flags are separate).
    pub msg_flags: i32,
}

impl MsgHdr {
    /// Create a new message header with no address, no control data,
    /// and the given I/O vectors.
    pub const fn new() -> Self {
        Self {
            name: None,
            name_len: 0,
            iov: [IoVec::new(0, 0); 8],
            iov_count: 0,
            control: [0u8; CMSG_BUF_MAX],
            control_len: 0,
            msg_flags: 0,
        }
    }

    /// Calculate the total data length across all `iov` entries.
    pub fn total_data_len(&self) -> usize {
        self.iov[..self.iov_count].iter().map(|v| v.size()).sum()
    }
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Result of a `sendmsg` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendResult {
    /// Total bytes sent.
    pub bytes_sent: usize,
}

/// Result of a `recvmsg` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecvResult {
    /// Total bytes received.
    pub bytes_received: usize,
    /// Flags set by the kernel (e.g., `MSG_TRUNC`, `MSG_CTRUNC`, `MSG_EOR`).
    pub msg_flags: i32,
    /// Ancillary data bytes returned.
    pub control_len: usize,
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate the `flags` argument for `sendmsg`.
fn validate_send_flags(flags: i32) -> Result<()> {
    if flags & !SENDMSG_VALID_FLAGS != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate the `flags` argument for `recvmsg`.
fn validate_recv_flags(flags: i32) -> Result<()> {
    if flags & !RECVMSG_VALID_FLAGS != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate a file descriptor (non-negative).
fn validate_fd(fd: i32) -> Result<()> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate the `iov_count` field.
fn validate_iov_count(count: usize) -> Result<()> {
    if count > IOV_MAX {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `sendmsg(2)`.
///
/// Sends a message described by `msg` on the socket `fd`.  The `flags`
/// argument modifies the transmission behaviour.
///
/// # Arguments
///
/// * `fd`    — The socket file descriptor.
/// * `msg`   — Message header describing address, data vectors, and ancillary data.
/// * `flags` — Send flags (e.g., `MSG_DONTWAIT`, `MSG_NOSIGNAL`).
///
/// # Return value
///
/// Returns the number of bytes sent on success.
///
/// # Errors
///
/// - `Error::InvalidArgument` — `fd < 0`, unknown flag bits, or `iov_count > IOV_MAX` (`EINVAL`).
/// - `Error::NotImplemented` — not yet connected to a real socket layer (`ENOSYS`).
///
/// # POSIX conformance
///
/// - Returns `EMSGSIZE` (mapped to `InvalidArgument`) if the message is too
///   large for the socket type.
/// - For connected sockets, the `name` field must be `None` (or the call
///   returns `EISCONN`).
/// - Zero-length `sendmsg` is permitted and returns 0 for stream sockets.
pub fn do_sendmsg(fd: i32, msg: &MsgHdr, flags: i32) -> Result<SendResult> {
    validate_fd(fd)?;
    validate_send_flags(flags)?;
    validate_iov_count(msg.iov_count)?;

    let total = msg.total_data_len();

    // A zero-length send on a stream socket is valid.
    if total == 0 && msg.control_len == 0 {
        return Ok(SendResult { bytes_sent: 0 });
    }

    // Stub: real implementation sends through the socket layer.
    Err(Error::NotImplemented)
}

/// Handler for `recvmsg(2)`.
///
/// Receives a message from socket `fd` into the buffers described by `msg`.
/// Sets `msg.msg_flags` to report any truncation or other receive-side events.
///
/// # Arguments
///
/// * `fd`    — The socket file descriptor.
/// * `msg`   — Message header; `iov` buffers are filled with received data.
/// * `flags` — Receive flags (e.g., `MSG_PEEK`, `MSG_WAITALL`).
///
/// # Return value
///
/// Returns the number of bytes received (the length of the message).
///
/// # Errors
///
/// - `Error::InvalidArgument` — `fd < 0`, unknown flag bits, or `iov_count > IOV_MAX`.
/// - `Error::WouldBlock` — No data available and `MSG_DONTWAIT` is set (or
///   socket is non-blocking) (`EAGAIN` / `EWOULDBLOCK`).
/// - `Error::NotImplemented` — not yet connected to a real socket layer.
///
/// # POSIX conformance
///
/// - If data is truncated, the `MSG_TRUNC` flag is set in `msg.msg_flags`.
/// - If control data is truncated, `MSG_CTRUNC` is set.
/// - `MSG_PEEK` does not consume the data; a subsequent `recvmsg` returns
///   the same data.
/// - For a zero-length datagram socket message, returns 0 without `MSG_TRUNC`.
pub fn do_recvmsg(fd: i32, msg: &mut MsgHdr, flags: i32) -> Result<RecvResult> {
    validate_fd(fd)?;
    validate_recv_flags(flags)?;
    validate_iov_count(msg.iov_count)?;

    // Stub: real implementation receives through the socket layer.
    Err(Error::NotImplemented)
}

// ---------------------------------------------------------------------------
// Ancillary data helpers
// ---------------------------------------------------------------------------

/// Build a control buffer containing a single `SCM_RIGHTS` message.
///
/// `SCM_RIGHTS` passes one or more file descriptors from sender to receiver
/// across a Unix domain socket.  The fds are serialised as an array of `i32`
/// values in the ancillary data payload.
///
/// Returns the number of bytes written to `buf`, or `Err(InvalidArgument)`
/// if `buf` is too small.
pub fn build_scm_rights(buf: &mut [u8], fds: &[i32]) -> Result<usize> {
    let data_len = fds.len() * core::mem::size_of::<i32>();
    let total = CmsgHdr::HEADER_SIZE + data_len;
    if buf.len() < total {
        return Err(Error::InvalidArgument);
    }

    let hdr = CmsgHdr {
        cmsg_len: total as u32,
        cmsg_level: SOL_SOCKET,
        cmsg_type: SCM_RIGHTS,
    };

    // Write header (little-endian).
    buf[0..4].copy_from_slice(&hdr.cmsg_len.to_le_bytes());
    buf[4..8].copy_from_slice(&hdr.cmsg_level.to_le_bytes());
    buf[8..12].copy_from_slice(&hdr.cmsg_type.to_le_bytes());

    // Write fd values.
    for (i, &fd) in fds.iter().enumerate() {
        let off = CmsgHdr::HEADER_SIZE + i * 4;
        buf[off..off + 4].copy_from_slice(&fd.to_le_bytes());
    }

    Ok(total)
}

/// Parse the first `CmsgHdr` from a control buffer.
///
/// Returns the parsed header and the offset to the ancillary data payload,
/// or `Err(InvalidArgument)` if the buffer is malformed.
pub fn parse_cmsg_hdr(buf: &[u8]) -> Result<(CmsgHdr, usize)> {
    if buf.len() < CmsgHdr::HEADER_SIZE {
        return Err(Error::InvalidArgument);
    }

    let cmsg_len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let cmsg_level = i32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let cmsg_type = i32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);

    let hdr = CmsgHdr {
        cmsg_len,
        cmsg_level,
        cmsg_type,
    };

    if (cmsg_len as usize) < CmsgHdr::HEADER_SIZE || (cmsg_len as usize) > buf.len() {
        return Err(Error::InvalidArgument);
    }

    Ok((hdr, CmsgHdr::HEADER_SIZE))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn basic_msg() -> MsgHdr {
        let mut msg = MsgHdr::new();
        msg.iov[0] = IoVec::new(0x1000, 16);
        msg.iov_count = 1;
        msg
    }

    // --- validation ---

    #[test]
    fn sendmsg_rejects_negative_fd() {
        let msg = basic_msg();
        assert_eq!(do_sendmsg(-1, &msg, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn sendmsg_rejects_unknown_flags() {
        let msg = basic_msg();
        assert_eq!(do_sendmsg(3, &msg, 0xDEAD), Err(Error::InvalidArgument));
    }

    #[test]
    fn recvmsg_rejects_negative_fd() {
        let mut msg = basic_msg();
        assert_eq!(do_recvmsg(-1, &mut msg, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn recvmsg_rejects_unknown_flags() {
        let mut msg = basic_msg();
        assert_eq!(do_recvmsg(3, &mut msg, 0x0200), Err(Error::InvalidArgument));
    }

    #[test]
    fn sendmsg_zero_length_returns_zero() {
        let msg = MsgHdr::new();
        let r = do_sendmsg(3, &msg, 0).unwrap();
        assert_eq!(r.bytes_sent, 0);
    }

    #[test]
    fn sendmsg_returns_not_implemented_for_data() {
        let msg = basic_msg();
        assert_eq!(do_sendmsg(3, &msg, 0), Err(Error::NotImplemented));
    }

    #[test]
    fn recvmsg_returns_not_implemented() {
        let mut msg = basic_msg();
        assert_eq!(do_recvmsg(3, &mut msg, 0), Err(Error::NotImplemented));
    }

    // --- MsgHdr ---

    #[test]
    fn msghdr_total_data_len() {
        let mut msg = MsgHdr::new();
        msg.iov[0] = IoVec::new(0, 100);
        msg.iov[1] = IoVec::new(0, 200);
        msg.iov_count = 2;
        assert_eq!(msg.total_data_len(), 300);
    }

    #[test]
    fn msghdr_zero_iov_count() {
        let msg = MsgHdr::new();
        assert_eq!(msg.total_data_len(), 0);
    }

    // --- CmsgHdr ---

    #[test]
    fn cmsg_hdr_data_len() {
        let hdr = CmsgHdr {
            cmsg_len: 20,
            cmsg_level: SOL_SOCKET,
            cmsg_type: SCM_RIGHTS,
        };
        assert_eq!(hdr.data_len(), 20 - CmsgHdr::HEADER_SIZE);
    }

    #[test]
    fn cmsg_hdr_data_len_too_short() {
        let hdr = CmsgHdr {
            cmsg_len: 4,
            cmsg_level: 0,
            cmsg_type: 0,
        };
        assert_eq!(hdr.data_len(), 0);
    }

    // --- SCM_RIGHTS builder ---

    #[test]
    fn build_scm_rights_single_fd() {
        let mut buf = [0u8; 64];
        let n = build_scm_rights(&mut buf, &[5]).unwrap();
        assert_eq!(n, CmsgHdr::HEADER_SIZE + 4);
        let (hdr, _) = parse_cmsg_hdr(&buf).unwrap();
        assert_eq!(hdr.cmsg_level, SOL_SOCKET);
        assert_eq!(hdr.cmsg_type, SCM_RIGHTS);
        let fd = i32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        assert_eq!(fd, 5);
    }

    #[test]
    fn build_scm_rights_multiple_fds() {
        let mut buf = [0u8; 64];
        let n = build_scm_rights(&mut buf, &[1, 2, 3]).unwrap();
        assert_eq!(n, CmsgHdr::HEADER_SIZE + 12);
    }

    #[test]
    fn build_scm_rights_buffer_too_small() {
        let mut buf = [0u8; 4];
        assert_eq!(
            build_scm_rights(&mut buf, &[1]),
            Err(Error::InvalidArgument)
        );
    }

    // --- cmsg parsing ---

    #[test]
    fn parse_cmsg_hdr_valid() {
        let mut buf = [0u8; 32];
        build_scm_rights(&mut buf, &[7]).unwrap();
        let (hdr, data_off) = parse_cmsg_hdr(&buf).unwrap();
        assert_eq!(hdr.cmsg_type, SCM_RIGHTS);
        assert_eq!(data_off, CmsgHdr::HEADER_SIZE);
    }

    #[test]
    fn parse_cmsg_hdr_too_short() {
        let buf = [0u8; 4];
        assert_eq!(parse_cmsg_hdr(&buf), Err(Error::InvalidArgument));
    }

    // --- flags validation ---

    #[test]
    fn sendmsg_accepts_valid_flags() {
        let msg = MsgHdr::new();
        // These flags pass validation; the stub returns NotImplemented (no data).
        // Zero-length with control_len=0 returns Ok(0).
        let r = do_sendmsg(3, &msg, MSG_NOSIGNAL | MSG_DONTWAIT);
        assert!(r.is_ok() || r == Err(Error::NotImplemented));
    }

    #[test]
    fn recvmsg_accepts_peek_flag() {
        let mut msg = basic_msg();
        // Should not reject MSG_PEEK; stub returns NotImplemented.
        assert_eq!(
            do_recvmsg(3, &mut msg, MSG_PEEK),
            Err(Error::NotImplemented)
        );
    }
}
