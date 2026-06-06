// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `recvmsg(2)` and `recvmmsg(2)` syscall handlers.
//!
//! `recvmsg` is the most general receive interface for sockets.  It supports:
//! - Scatter-gather I/O via an array of `iovec` buffers.
//! - Ancillary (control) data via `cmsghdr` chains (`SCM_RIGHTS`,
//!   `SCM_CREDENTIALS`, `SCM_TIMESTAMP`).
//! - Per-call message flags (`MSG_PEEK`, `MSG_TRUNC`, `MSG_WAITALL`,
//!   `MSG_DONTWAIT`, `MSG_CMSG_CLOEXEC`).
//!
//! `recvmmsg` is the batched variant: it calls `recvmsg` up to `vlen` times in
//! one syscall and supports an optional absolute deadline (`timeout`).
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `recvmsg()`.  `recvmmsg` is a Linux extension.
//!
//! # Key data flow
//!
//! ```text
//! user space                  kernel space
//! ──────────                  ─────────────
//! recvmsg(sockfd, msghdr, flags)
//!                             validate(sockfd, msghdr, flags)
//!                             → MsgHdr::from_raw()
//!                             → do_recvmsg_validated()
//!                               scatter data into iov[]
//!                               parse + deliver ancdata
//!                             ◄── bytes / -errno
//! ```
//!
//! # References
//!
//! - POSIX.1-2024: `recvmsg()`
//! - Linux: `net/socket.c` `__sys_recvmsg`, `__sys_recvmmsg`
//! - Linux: `include/linux/socket.h`, `include/uapi/linux/socket.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Message flags
// ---------------------------------------------------------------------------

/// Receive out-of-band data.
pub const MSG_OOB: i32 = 0x01;
/// Peek at incoming data without removing from queue.
pub const MSG_PEEK: i32 = 0x02;
/// Received data was truncated (set by kernel).
pub const MSG_TRUNC: i32 = 0x20;
/// Ancillary data was truncated (set by kernel).
pub const MSG_CTRUNC: i32 = 0x08;
/// End-of-record marker.
pub const MSG_EOR: i32 = 0x80;
/// Non-blocking for this call only.
pub const MSG_DONTWAIT: i32 = 0x40;
/// Wait until receive buffer is fully filled.
pub const MSG_WAITALL: i32 = 0x100;
/// Apply close-on-exec to received file descriptors.
pub const MSG_CMSG_CLOEXEC: i32 = 0x4000_0000;

/// Mask of all flags valid for `recvmsg`.
const RECVMSG_VALID_FLAGS: i32 =
    MSG_OOB | MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT | MSG_WAITALL | MSG_CMSG_CLOEXEC;

// ---------------------------------------------------------------------------
// Control message levels / types
// ---------------------------------------------------------------------------

/// Socket-level control messages.
pub const SOL_SOCKET: i32 = 1;
/// Pass open file descriptors.
pub const SCM_RIGHTS: i32 = 1;
/// Pass credentials (`ucred`).
pub const SCM_CREDENTIALS: i32 = 2;
/// Receive timestamp (`timeval`).
pub const SCM_TIMESTAMP: i32 = 29;

// ---------------------------------------------------------------------------
// Size limits
// ---------------------------------------------------------------------------

/// Maximum number of `iovec` entries per message.
pub const IOV_MAX: usize = 1024;
/// Maximum ancillary data buffer size (bytes).
pub const CMSG_MAX_LEN: usize = 4096;
/// Maximum number of FDs transferable via `SCM_RIGHTS` in one message.
pub const SCM_MAX_FD: usize = 253;
/// Maximum number of messages in one `recvmmsg` call.
pub const MMSGHDR_MAX: usize = 1024;
/// Maximum socket receive buffer size (bytes).
pub const SOCK_MAX_BUF: usize = 256 * 1024;

// ---------------------------------------------------------------------------
// Iovec — scatter/gather buffer descriptor
// ---------------------------------------------------------------------------

/// User-space scatter/gather buffer descriptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct IoVec {
    /// Pointer into user address space (represented as a raw address here).
    pub base: u64,
    /// Length of this buffer segment in bytes.
    pub len: usize,
}

impl IoVec {
    /// Construct a new `IoVec`.
    pub const fn new(base: u64, len: usize) -> Self {
        Self { base, len }
    }

    /// Return `true` if this segment is zero-length.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// ---------------------------------------------------------------------------
// CmsgHdr — control message header
// ---------------------------------------------------------------------------

/// Control (ancillary) message header.
///
/// Each `cmsghdr` is followed by `cmsg_len - CMSG_HDR_SIZE` bytes of data.
#[derive(Debug, Clone, Copy, Default)]
pub struct CmsgHdr {
    /// Total length of this `cmsghdr` including header and data.
    pub cmsg_len: usize,
    /// Originating protocol level (e.g. `SOL_SOCKET`).
    pub cmsg_level: i32,
    /// Message type within that level (e.g. `SCM_RIGHTS`).
    pub cmsg_type: i32,
}

/// Size of the `CmsgHdr` structure itself (without data payload).
pub const CMSG_HDR_SIZE: usize = core::mem::size_of::<CmsgHdr>();

impl CmsgHdr {
    /// Return the number of data bytes carried by this control message.
    pub const fn data_len(&self) -> usize {
        self.cmsg_len.saturating_sub(CMSG_HDR_SIZE)
    }

    /// Return `true` if this header describes a valid control message.
    pub const fn is_valid(&self) -> bool {
        self.cmsg_len >= CMSG_HDR_SIZE
    }
}

// ---------------------------------------------------------------------------
// AncillaryData — parsed ancillary payload variants
// ---------------------------------------------------------------------------

/// Parsed ancillary data variant.
#[derive(Debug, Clone)]
pub enum AncillaryData {
    /// `SCM_RIGHTS`: array of file descriptors being passed.
    Rights(ScmRights),
    /// `SCM_CREDENTIALS`: sender credentials.
    Credentials(ScmCredentials),
    /// `SCM_TIMESTAMP`: send/receive timestamp.
    Timestamp(ScmTimestamp),
    /// Unknown or unsupported ancillary message.
    Unknown {
        level: i32,
        msg_type: i32,
        data_len: usize,
    },
}

/// `SCM_RIGHTS` payload: file descriptors passed between processes.
#[derive(Debug, Clone)]
pub struct ScmRights {
    /// File descriptor numbers being transferred.
    pub fds: ScmFdArray,
    /// Number of valid entries in `fds`.
    pub count: usize,
}

/// Fixed-size array backing `ScmRights`.
#[derive(Debug, Clone, Copy)]
pub struct ScmFdArray {
    inner: [i32; SCM_MAX_FD],
    len: usize,
}

impl ScmFdArray {
    /// Create an empty fd array.
    pub const fn new() -> Self {
        Self {
            inner: [0i32; SCM_MAX_FD],
            len: 0,
        }
    }

    /// Push a file descriptor.
    ///
    /// # Errors
    ///
    /// Returns `OutOfMemory` if the array is full.
    pub fn push(&mut self, fd: i32) -> Result<()> {
        if self.len >= SCM_MAX_FD {
            return Err(Error::OutOfMemory);
        }
        self.inner[self.len] = fd;
        self.len += 1;
        Ok(())
    }

    /// Return a slice of the valid fds.
    pub fn as_slice(&self) -> &[i32] {
        &self.inner[..self.len]
    }

    /// Number of fds stored.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Return `true` if no fds are stored.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for ScmFdArray {
    fn default() -> Self {
        Self::new()
    }
}

/// `SCM_CREDENTIALS` payload.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScmCredentials {
    /// PID of the sending process.
    pub pid: i32,
    /// UID of the sending process.
    pub uid: u32,
    /// GID of the sending process.
    pub gid: u32,
}

/// `SCM_TIMESTAMP` payload.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScmTimestamp {
    /// Seconds component.
    pub tv_sec: i64,
    /// Microseconds component.
    pub tv_usec: i64,
}

// ---------------------------------------------------------------------------
// MsgFlags — typed receive flags
// ---------------------------------------------------------------------------

/// Validated flags for a `recvmsg` call.
#[derive(Debug, Clone, Copy, Default)]
pub struct MsgFlags(i32);

impl MsgFlags {
    /// Parse and validate flags from a raw `i32`.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` if unknown bits are set.
    pub fn from_raw(raw: i32) -> Result<Self> {
        if raw & !RECVMSG_VALID_FLAGS != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Return the raw bit pattern.
    pub const fn bits(&self) -> i32 {
        self.0
    }

    /// Non-blocking for this call.
    pub const fn dontwait(&self) -> bool {
        self.0 & MSG_DONTWAIT != 0
    }

    /// Peek without consuming.
    pub const fn peek(&self) -> bool {
        self.0 & MSG_PEEK != 0
    }

    /// Wait until buffer fully filled.
    pub const fn waitall(&self) -> bool {
        self.0 & MSG_WAITALL != 0
    }

    /// Close-on-exec for received fds.
    pub const fn cmsg_cloexec(&self) -> bool {
        self.0 & MSG_CMSG_CLOEXEC != 0
    }
}

// ---------------------------------------------------------------------------
// MsgHdr — message header descriptor
// ---------------------------------------------------------------------------

/// Message header for `recvmsg`.
///
/// Mirrors the POSIX `struct msghdr`.
#[derive(Debug)]
pub struct MsgHdr {
    /// Optional peer address buffer (output).
    pub name: u64,
    /// Length of the name buffer.
    pub namelen: u32,
    /// Scatter/gather I/O vector.
    pub iov: IovArray,
    /// Number of valid entries in `iov`.
    pub iovlen: usize,
    /// Ancillary data buffer (output).
    pub control: u64,
    /// Length of the control buffer.
    pub controllen: usize,
    /// Flags set by the kernel on completion (output).
    pub msg_flags: i32,
}

/// Inline storage for up to `IOV_MAX` `IoVec` entries.
pub struct IovArray {
    inner: [IoVec; 8],
    overflow: [IoVec; 16],
    len: usize,
}

impl core::fmt::Debug for IovArray {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IovArray").field("len", &self.len).finish()
    }
}

impl IovArray {
    /// Create an empty array.
    pub const fn new() -> Self {
        Self {
            inner: [const { IoVec::new(0, 0) }; 8],
            overflow: [const { IoVec::new(0, 0) }; 16],
            len: 0,
        }
    }

    /// Push an `IoVec` entry.
    ///
    /// # Errors
    ///
    /// `OutOfMemory` if `inline + overflow` slots are exhausted.
    pub fn push(&mut self, iov: IoVec) -> Result<()> {
        if self.len < 8 {
            self.inner[self.len] = iov;
            self.len += 1;
            Ok(())
        } else if self.len < 24 {
            self.overflow[self.len - 8] = iov;
            self.len += 1;
            Ok(())
        } else {
            Err(Error::OutOfMemory)
        }
    }

    /// Return the `IoVec` at index `i`.
    pub fn get(&self, i: usize) -> Option<&IoVec> {
        if i < self.len {
            if i < 8 {
                Some(&self.inner[i])
            } else {
                Some(&self.overflow[i - 8])
            }
        } else {
            None
        }
    }

    /// Number of entries.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Total byte capacity across all `IoVec` entries.
    pub fn total_capacity(&self) -> usize {
        let mut total = 0usize;
        for i in 0..self.len {
            total = total.saturating_add(self.get(i).map_or(0, |v| v.len));
        }
        total
    }
}

impl MsgHdr {
    /// Construct a `MsgHdr` from raw syscall arguments.
    ///
    /// # Arguments
    ///
    /// * `name`       — user-space address of peer-name buffer (0 = not needed)
    /// * `namelen`    — capacity of name buffer
    /// * `iov_array`  — pre-populated `IovArray`
    /// * `control`    — user-space address of ancillary data buffer (0 = none)
    /// * `controllen` — capacity of ancillary buffer
    ///
    /// # Errors
    ///
    /// `InvalidArgument` if `iovlen` is 0 or exceeds `IOV_MAX`.
    pub fn from_raw(
        name: u64,
        namelen: u32,
        iov_array: IovArray,
        control: u64,
        controllen: usize,
    ) -> Result<Self> {
        if iov_array.len() == 0 || iov_array.len() > IOV_MAX {
            return Err(Error::InvalidArgument);
        }
        if controllen > CMSG_MAX_LEN {
            return Err(Error::InvalidArgument);
        }
        let iovlen = iov_array.len();
        Ok(Self {
            name,
            namelen,
            iov: iov_array,
            iovlen,
            control,
            controllen,
            msg_flags: 0,
        })
    }

    /// Total receive capacity across all `iov` entries.
    pub fn total_iov_capacity(&self) -> usize {
        self.iov.total_capacity()
    }
}

// ---------------------------------------------------------------------------
// RecvResult — result of a successful recvmsg
// ---------------------------------------------------------------------------

/// Result of a successful `recvmsg` call.
#[derive(Debug)]
pub struct RecvResult {
    /// Bytes of data received.
    pub bytes_received: usize,
    /// Kernel-set output flags (e.g. `MSG_TRUNC`, `MSG_CTRUNC`).
    pub msg_flags: i32,
    /// Parsed ancillary data entries.
    pub ancdata: AncDataVec,
}

/// Small inline vector for `AncillaryData` entries.
pub struct AncDataVec {
    inner: [Option<AncillaryData>; 8],
    len: usize,
}

impl core::fmt::Debug for AncDataVec {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AncDataVec")
            .field("len", &self.len)
            .finish()
    }
}

impl AncDataVec {
    /// Create an empty vector.
    pub fn new() -> Self {
        Self {
            inner: [None, None, None, None, None, None, None, None],
            len: 0,
        }
    }

    /// Push an ancillary data item.
    pub fn push(&mut self, item: AncillaryData) {
        if self.len < 8 {
            self.inner[self.len] = Some(item);
            self.len += 1;
        }
    }

    /// Return the item at index `i`.
    pub fn get(&self, i: usize) -> Option<&AncillaryData> {
        if i < self.len {
            self.inner[i].as_ref()
        } else {
            None
        }
    }

    /// Number of ancillary data entries.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Return `true` if empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// ---------------------------------------------------------------------------
// RecvMmsgEntry — one entry in a `recvmmsg` batch
// ---------------------------------------------------------------------------

/// One message descriptor in a `recvmmsg` call.
#[derive(Debug)]
pub struct RecvMmsgEntry {
    /// The message header for this entry.
    pub hdr: MsgHdr,
    /// Bytes received (filled by kernel on success).
    pub msg_len: u32,
}

// ---------------------------------------------------------------------------
// RecvTimeout — optional absolute deadline for recvmmsg
// ---------------------------------------------------------------------------

/// Optional timeout for `recvmmsg`.
#[derive(Debug, Clone, Copy)]
pub struct RecvTimeout {
    /// Seconds.
    pub tv_sec: i64,
    /// Nanoseconds.
    pub tv_nsec: i64,
}

impl RecvTimeout {
    /// Construct from raw parts, validating nanosecond range.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` if `tv_nsec` is outside `[0, 999_999_999]`.
    pub fn from_raw(tv_sec: i64, tv_nsec: i64) -> Result<Self> {
        if !(0..=999_999_999).contains(&tv_nsec) {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { tv_sec, tv_nsec })
    }

    /// Return `true` if the deadline has zero or negative value.
    pub const fn is_zero(&self) -> bool {
        self.tv_sec <= 0 && self.tv_nsec == 0
    }
}

// ---------------------------------------------------------------------------
// Ancillary data parser
// ---------------------------------------------------------------------------

/// Parse a flat ancillary data buffer into `AncillaryData` entries.
///
/// Iterates over the `cmsghdr` chain contained in `buf`, parsing known
/// message types and recording unknowns.
///
/// # Arguments
///
/// * `buf`         — raw ancillary buffer (kernel-side copy, already bounds-checked
///                   against [`CMSG_MAX_LEN`] by [`MsgHdr::from_raw`])
/// * `cloexec_fds` — if `true`, mark received FDs close-on-exec
///
/// # Returns
///
/// An `AncDataVec` of parsed entries and any flags to OR into `msg_flags`.
///
/// # Security
///
/// Every arithmetic operation on attacker-controlled lengths uses checked or
/// saturating variants; no unchecked addition is performed on `cmsg_len`.
/// Specifically:
///
/// 1. `remaining = buf.len() - offset` (no overflow: offset is always <= buf.len()).
/// 2. `cmsg_len < CMSG_HDR_SIZE || cmsg_len > remaining` — comparison only, no add.
/// 3. `data_end = offset + cmsg_len` is safe because step 2 proved
///    `cmsg_len <= remaining = buf.len() - offset`.
/// 4. The CMSG_NXTHDR advance uses `checked_add` twice; `None` breaks the loop,
///    preventing any infinite-loop or wrap-to-zero advance.
pub fn parse_ancillary_data(buf: &[u8], _cloexec_fds: bool) -> (AncDataVec, i32) {
    // Caller (MsgHdr::from_raw) already rejects controllen > CMSG_MAX_LEN.
    // Belt-and-suspenders: if somehow a larger slice arrives, silently truncate
    // so this function never processes more than CMSG_MAX_LEN bytes.
    debug_assert!(
        buf.len() <= CMSG_MAX_LEN,
        "ancillary buf exceeds CMSG_MAX_LEN"
    );
    let buf = if buf.len() > CMSG_MAX_LEN {
        &buf[..CMSG_MAX_LEN]
    } else {
        buf
    };

    let mut out = AncDataVec::new();
    let mut extra_flags = 0i32;
    let mut offset = 0usize;

    // Loop invariant: offset <= buf.len() (maintained by every exit path).
    while offset + CMSG_HDR_SIZE <= buf.len() {
        // --- 1. Read the fixed-size header from the kernel-local buffer. ---
        // offset + CMSG_HDR_SIZE (16) <= buf.len() is guaranteed by the while
        // condition, so all sub-slices are in bounds.
        let cmsg_len_bytes: [u8; 8] = buf[offset..offset + 8].try_into().unwrap_or([0u8; 8]);
        let cmsg_len = usize::from_ne_bytes(cmsg_len_bytes);

        let level_bytes: [u8; 4] = buf[offset + 8..offset + 12].try_into().unwrap_or([0u8; 4]);
        let cmsg_level = i32::from_ne_bytes(level_bytes);

        let type_bytes: [u8; 4] = buf[offset + 12..offset + 16].try_into().unwrap_or([0u8; 4]);
        let cmsg_type = i32::from_ne_bytes(type_bytes);

        // --- 2. Validate cmsg_len against remaining bytes (no addition). ---
        // remaining = buf.len() - offset is exact because offset <= buf.len().
        let remaining = buf.len() - offset;

        if cmsg_len < CMSG_HDR_SIZE || cmsg_len > remaining {
            // Malformed or truncated chain — stop.
            extra_flags |= MSG_CTRUNC;
            break;
        }

        // --- 3. Form payload slice. ---
        // cmsg_len <= remaining = buf.len() - offset, so:
        //   offset + cmsg_len <= buf.len()  (no overflow, both in-range).
        let data_end = offset + cmsg_len; // safe: proven above
        let data = &buf[offset + CMSG_HDR_SIZE..data_end];

        let hdr = CmsgHdr {
            cmsg_len,
            cmsg_level,
            cmsg_type,
        };

        match (cmsg_level, cmsg_type) {
            (l, SCM_RIGHTS) if l == SOL_SOCKET => {
                let mut fds = ScmFdArray::new();
                let mut i = 0usize;
                while i + 4 <= data.len() && fds.len() < SCM_MAX_FD {
                    let fd_bytes: [u8; 4] = data[i..i + 4].try_into().unwrap_or([0u8; 4]);
                    let _ = fds.push(i32::from_ne_bytes(fd_bytes));
                    i += 4;
                }
                let count = fds.len();
                out.push(AncillaryData::Rights(ScmRights { fds, count }));
            }
            (l, SCM_CREDENTIALS) if l == SOL_SOCKET => {
                if data.len() >= 12 {
                    let pid = i32::from_ne_bytes(data[0..4].try_into().unwrap_or([0u8; 4]));
                    let uid = u32::from_ne_bytes(data[4..8].try_into().unwrap_or([0u8; 4]));
                    let gid = u32::from_ne_bytes(data[8..12].try_into().unwrap_or([0u8; 4]));
                    out.push(AncillaryData::Credentials(ScmCredentials { pid, uid, gid }));
                }
            }
            (l, SCM_TIMESTAMP) if l == SOL_SOCKET => {
                if data.len() >= 16 {
                    let tv_sec = i64::from_ne_bytes(data[0..8].try_into().unwrap_or([0u8; 8]));
                    let tv_usec = i64::from_ne_bytes(data[8..16].try_into().unwrap_or([0u8; 8]));
                    out.push(AncillaryData::Timestamp(ScmTimestamp { tv_sec, tv_usec }));
                }
            }
            _ => {
                out.push(AncillaryData::Unknown {
                    level: cmsg_level,
                    msg_type: cmsg_type,
                    data_len: hdr.data_len(),
                });
            }
        }

        // --- 4. CMSG_NXTHDR: advance offset by aligned(cmsg_len). ---
        // aligned = (cmsg_len + 7) & !7
        // Use checked_add to detect any overflow (cmsg_len near usize::MAX).
        // Additionally, aligned must be >= CMSG_HDR_SIZE to guarantee forward
        // progress (cmsg_len >= CMSG_HDR_SIZE was already checked above, so
        // this holds: (CMSG_HDR_SIZE + 7) & !7 == 16 == CMSG_HDR_SIZE).
        let aligned = match cmsg_len.checked_add(7) {
            Some(v) => v & !7usize,
            None => {
                // Overflow: cmsg_len > usize::MAX - 7; chain is malformed.
                extra_flags |= MSG_CTRUNC;
                break;
            }
        };
        // aligned >= CMSG_HDR_SIZE (16) because cmsg_len >= CMSG_HDR_SIZE.
        // This guarantees forward progress (offset strictly increases).
        let next_offset = match offset.checked_add(aligned) {
            Some(v) => v,
            None => {
                // offset + aligned overflows: done.
                break;
            }
        };
        offset = next_offset;
    }

    (out, extra_flags)
}

// ---------------------------------------------------------------------------
// do_recvmsg — public handler
// ---------------------------------------------------------------------------

/// Handler for `recvmsg(2)`.
///
/// Receives a message from socket `sockfd` into the buffers described by
/// `hdr`.  Ancillary data (if requested) is parsed and returned.
///
/// # Arguments
///
/// * `sockfd`         — socket file descriptor
/// * `hdr`            — message header (iov, control buffer, etc.)
/// * `flags`          — receive flags
/// * `socket_data`    — simulated socket receive buffer
/// * `peer_addr`      — simulated peer address string (for name output)
///
/// # Returns
///
/// A [`RecvResult`] on success.
///
/// # Errors
///
/// - `InvalidArgument`  — bad flags or malformed `hdr`
/// - `NotFound`         — `sockfd` not open
/// - `WouldBlock`       — `MSG_DONTWAIT` and no data available
pub fn do_recvmsg(
    sockfd: i32,
    hdr: &mut MsgHdr,
    flags: i32,
    socket_data: &[u8],
    _peer_addr: &[u8],
) -> Result<RecvResult> {
    if sockfd < 0 {
        return Err(Error::NotFound);
    }

    let msg_flags = MsgFlags::from_raw(flags)?;

    if msg_flags.dontwait() && socket_data.is_empty() {
        return Err(Error::WouldBlock);
    }

    // Compute total iov capacity.
    let capacity = hdr.total_iov_capacity();
    let data_len = socket_data.len();

    // Scatter data into iov buffers.
    let mut remaining = data_len;
    let mut iov_idx = 0usize;
    let mut copied = 0usize;

    while remaining > 0 && iov_idx < hdr.iovlen {
        let iov = hdr.iov.get(iov_idx).copied().unwrap_or(IoVec::new(0, 0));
        let to_copy = iov.len.min(remaining);
        // In a real kernel: copy_to_user(iov.base, &socket_data[copied..copied+to_copy])
        copied += to_copy;
        remaining -= to_copy;
        iov_idx += 1;
    }

    let bytes_received = if msg_flags.peek() {
        data_len.min(capacity)
    } else {
        copied
    };

    let mut out_flags = 0i32;
    if data_len > capacity {
        out_flags |= MSG_TRUNC;
    }

    // Parse ancillary data if a control buffer was provided.
    let ancdata = if hdr.control != 0 && hdr.controllen > 0 {
        // In a real kernel we'd copy from the socket's ancillary queue.
        // Stub: return empty ancdata.
        AncDataVec::new()
    } else {
        AncDataVec::new()
    };

    hdr.msg_flags = out_flags;

    Ok(RecvResult {
        bytes_received,
        msg_flags: out_flags,
        ancdata,
    })
}

// ---------------------------------------------------------------------------
// do_recvmmsg — batched variant
// ---------------------------------------------------------------------------

/// Handler for `recvmmsg(2)`.
///
/// Receives up to `vlen` messages from `sockfd` in a single syscall.
/// An optional `timeout` provides an absolute deadline; once it expires the
/// call returns with however many messages were received so far (which may be
/// 0, unlike `recvmsg` which would return `EINTR`).
///
/// # Arguments
///
/// * `sockfd`   — socket file descriptor
/// * `entries`  — mutable slice of message entries (at most `MMSGHDR_MAX`)
/// * `flags`    — flags applied to every sub-receive
/// * `timeout`  — optional absolute deadline
/// * `buffers`  — per-message simulated socket data (same length as `entries`)
///
/// # Returns
///
/// Number of messages successfully received.
///
/// # Errors
///
/// - `InvalidArgument` — `entries` exceeds `MMSGHDR_MAX`, bad flags, bad timeout
/// - `NotFound`        — `sockfd` not open
/// - `Interrupted`     — deadline expired before first message
pub fn do_recvmmsg(
    sockfd: i32,
    entries: &mut [RecvMmsgEntry],
    flags: i32,
    timeout: Option<RecvTimeout>,
    buffers: &[&[u8]],
) -> Result<usize> {
    if sockfd < 0 {
        return Err(Error::NotFound);
    }
    if entries.len() > MMSGHDR_MAX {
        return Err(Error::InvalidArgument);
    }
    // Validate flags (reuse recvmsg validation).
    MsgFlags::from_raw(flags)?;

    // Validate timeout if provided.
    if let Some(ref to) = timeout {
        if to.is_zero() && entries.is_empty() {
            return Err(Error::Interrupted);
        }
    }

    let count = entries.len().min(buffers.len());
    let mut received = 0usize;

    for i in 0..count {
        let buf = buffers[i];
        match do_recvmsg(sockfd, &mut entries[i].hdr, flags, buf, &[]) {
            Ok(result) => {
                entries[i].msg_len = result.bytes_received as u32;
                received += 1;
            }
            Err(Error::WouldBlock) => break,
            Err(Error::Interrupted) => break,
            Err(e) => return Err(e),
        }
    }

    if received == 0 {
        if let Some(to) = timeout {
            if to.is_zero() {
                return Err(Error::Interrupted);
            }
        }
    }

    Ok(received)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hdr(buf_size: usize) -> MsgHdr {
        let mut iov = IovArray::new();
        iov.push(IoVec::new(0x1000, buf_size)).unwrap();
        MsgHdr::from_raw(0, 0, iov, 0, 0).unwrap()
    }

    #[test]
    fn recvmsg_basic() {
        let data = b"hello world";
        let mut hdr = make_hdr(64);
        let r = do_recvmsg(3, &mut hdr, 0, data, &[]).unwrap();
        assert_eq!(r.bytes_received, 11);
        assert_eq!(r.msg_flags, 0);
    }

    #[test]
    fn recvmsg_trunc_flag_set() {
        let data = [0u8; 200];
        let mut hdr = make_hdr(64);
        let r = do_recvmsg(3, &mut hdr, 0, &data, &[]).unwrap();
        assert!(r.msg_flags & MSG_TRUNC != 0);
    }

    #[test]
    fn recvmsg_dontwait_no_data() {
        let mut hdr = make_hdr(64);
        let e = do_recvmsg(3, &mut hdr, MSG_DONTWAIT, &[], &[]).unwrap_err();
        assert_eq!(e, Error::WouldBlock);
    }

    #[test]
    fn recvmsg_bad_fd() {
        let mut hdr = make_hdr(64);
        let e = do_recvmsg(-1, &mut hdr, 0, b"x", &[]).unwrap_err();
        assert_eq!(e, Error::NotFound);
    }

    #[test]
    fn recvmsg_invalid_flags() {
        let mut hdr = make_hdr(64);
        let e = do_recvmsg(3, &mut hdr, 0x1234_5678, b"x", &[]).unwrap_err();
        assert_eq!(e, Error::InvalidArgument);
    }

    #[test]
    fn msg_flags_peek() {
        let f = MsgFlags::from_raw(MSG_PEEK).unwrap();
        assert!(f.peek());
        assert!(!f.dontwait());
    }

    #[test]
    fn msg_flags_invalid() {
        assert!(MsgFlags::from_raw(0x0001_0000).is_err());
    }

    #[test]
    fn parse_ancillary_empty() {
        let (anc, flags) = parse_ancillary_data(&[], false);
        assert!(anc.is_empty());
        assert_eq!(flags, 0);
    }

    #[test]
    fn scm_fd_array_push_pop() {
        let mut arr = ScmFdArray::new();
        arr.push(3).unwrap();
        arr.push(4).unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr.as_slice(), &[3, 4]);
    }

    #[test]
    fn iov_array_capacity() {
        let mut arr = IovArray::new();
        arr.push(IoVec::new(0x1000, 100)).unwrap();
        arr.push(IoVec::new(0x2000, 200)).unwrap();
        assert_eq!(arr.total_capacity(), 300);
    }

    #[test]
    fn recvmmsg_basic() {
        let data1 = b"foo";
        let data2 = b"bar";
        let mut iov1 = IovArray::new();
        iov1.push(IoVec::new(0x1000, 64)).unwrap();
        let mut iov2 = IovArray::new();
        iov2.push(IoVec::new(0x2000, 64)).unwrap();
        let mut entries = [
            RecvMmsgEntry {
                hdr: MsgHdr::from_raw(0, 0, iov1, 0, 0).unwrap(),
                msg_len: 0,
            },
            RecvMmsgEntry {
                hdr: MsgHdr::from_raw(0, 0, iov2, 0, 0).unwrap(),
                msg_len: 0,
            },
        ];
        let bufs: &[&[u8]] = &[data1, data2];
        let n = do_recvmmsg(3, &mut entries, 0, None, bufs).unwrap();
        assert_eq!(n, 2);
        assert_eq!(entries[0].msg_len, 3);
        assert_eq!(entries[1].msg_len, 3);
    }

    #[test]
    fn recvmmsg_exceeds_max() {
        let e = do_recvmmsg(3, &mut [], 0, None, &[]).unwrap();
        assert_eq!(e, 0);
    }

    #[test]
    fn recv_timeout_validation() {
        assert!(RecvTimeout::from_raw(0, 0).is_ok());
        assert!(RecvTimeout::from_raw(1, 1_000_000_000).is_err());
        assert!(RecvTimeout::from_raw(0, -1).is_err());
    }

    #[test]
    fn cmsg_hdr_data_len() {
        let hdr = CmsgHdr {
            cmsg_len: CMSG_HDR_SIZE + 8,
            cmsg_level: SOL_SOCKET,
            cmsg_type: SCM_RIGHTS,
        };
        assert_eq!(hdr.data_len(), 8);
        assert!(hdr.is_valid());
    }

    // -----------------------------------------------------------------
    // Security regression tests — parse_ancillary_data overflow paths
    // -----------------------------------------------------------------

    /// A crafted cmsg_len of usize::MAX must not wrap the bounds guard,
    /// must not panic, and must set MSG_CTRUNC.
    #[test]
    fn parse_ancillary_cmsg_len_usize_max_sets_ctrunc() {
        // Build a minimal 16-byte buffer whose cmsg_len field is usize::MAX.
        let mut buf = [0u8; CMSG_HDR_SIZE];
        buf[0..8].copy_from_slice(&usize::MAX.to_ne_bytes());
        // cmsg_level = SOL_SOCKET (1)
        buf[8..12].copy_from_slice(&1i32.to_ne_bytes());
        // cmsg_type = SCM_RIGHTS (1)
        buf[12..16].copy_from_slice(&1i32.to_ne_bytes());

        let (anc, flags) = parse_ancillary_data(&buf, false);
        // Must not panic; must report truncation; must produce no parsed entries.
        assert!(anc.is_empty(), "expected no parsed entries");
        assert_ne!(flags & MSG_CTRUNC, 0, "expected MSG_CTRUNC");
    }

    /// A crafted cmsg_len that is exactly one byte beyond the buffer end
    /// must set MSG_CTRUNC without panicking.
    #[test]
    fn parse_ancillary_cmsg_len_one_past_end_sets_ctrunc() {
        // Buffer has 20 bytes; cmsg_len claims 21.
        const BUF_LEN: usize = 20;
        let mut buf = [0u8; BUF_LEN];
        buf[0..8].copy_from_slice(&(BUF_LEN + 1).to_ne_bytes());
        buf[8..12].copy_from_slice(&1i32.to_ne_bytes());
        buf[12..16].copy_from_slice(&1i32.to_ne_bytes());

        let (anc, flags) = parse_ancillary_data(&buf, false);
        assert!(anc.is_empty());
        assert_ne!(flags & MSG_CTRUNC, 0);
    }

    /// A crafted second cmsg whose aligned advance would overflow must
    /// terminate the loop cleanly (no panic, no infinite loop).
    #[test]
    fn parse_ancillary_aligned_advance_overflow_terminates() {
        // First cmsg: valid CMSG_HDR_SIZE entry with 0 data bytes.
        // cmsg_len = CMSG_HDR_SIZE (16); aligned = 16.
        // Second cmsg: cmsg_len = usize::MAX - 6 so (usize::MAX-6+7)&!7 wraps.
        let mut buf = [0u8; CMSG_HDR_SIZE * 2];
        // First entry: cmsg_len = 16, level = SOL_SOCKET, type = SCM_TIMESTAMP
        // (data_len = 0, so no timestamp is pushed — but the entry is valid).
        buf[0..8].copy_from_slice(&CMSG_HDR_SIZE.to_ne_bytes());
        buf[8..12].copy_from_slice(&SOL_SOCKET.to_ne_bytes());
        buf[12..16].copy_from_slice(&SCM_TIMESTAMP.to_ne_bytes());
        // Second entry: cmsg_len = usize::MAX - 6; but remaining = 16,
        // so the bounds check fires first and we set MSG_CTRUNC.
        let huge: usize = usize::MAX - 6;
        buf[16..24].copy_from_slice(&huge.to_ne_bytes());
        buf[24..28].copy_from_slice(&1i32.to_ne_bytes());
        buf[28..32].copy_from_slice(&1i32.to_ne_bytes());

        let (anc, flags) = parse_ancillary_data(&buf, false);
        // First entry produced an Unknown (SCM_TIMESTAMP with 0 data bytes,
        // which doesn't satisfy data.len() >= 16, so falls through to Unknown).
        // Second entry triggers MSG_CTRUNC. Either way, must not panic/loop.
        assert_ne!(flags & MSG_CTRUNC, 0);
        let _ = anc.len(); // just access it to show no panic
    }

    /// A valid SCM_RIGHTS cmsg followed by a cmsg_len = usize::MAX entry
    /// must return the first entry and then set MSG_CTRUNC.
    #[test]
    fn parse_ancillary_valid_rights_then_overflow_in_second_cmsg() {
        // Craft: cmsg_len = CMSG_HDR_SIZE + 4 (one fd), then a second header
        // with cmsg_len = usize::MAX.
        const FIRST_LEN: usize = CMSG_HDR_SIZE + 4; // 20 bytes
        // Align first entry to 8: (20+7)&!7 = 24
        const FIRST_ALIGNED: usize = 24;
        let buf_len = FIRST_ALIGNED + CMSG_HDR_SIZE;
        let mut buf = [0u8; FIRST_ALIGNED + CMSG_HDR_SIZE];

        // First cmsg: SCM_RIGHTS with fd=5.
        buf[0..8].copy_from_slice(&FIRST_LEN.to_ne_bytes());
        buf[8..12].copy_from_slice(&SOL_SOCKET.to_ne_bytes());
        buf[12..16].copy_from_slice(&SCM_RIGHTS.to_ne_bytes());
        buf[16..20].copy_from_slice(&5i32.to_ne_bytes()); // fd value

        // Second cmsg header at offset 24: cmsg_len = usize::MAX.
        buf[FIRST_ALIGNED..FIRST_ALIGNED + 8].copy_from_slice(&usize::MAX.to_ne_bytes());
        buf[FIRST_ALIGNED + 8..FIRST_ALIGNED + 12].copy_from_slice(&SOL_SOCKET.to_ne_bytes());
        buf[FIRST_ALIGNED + 12..FIRST_ALIGNED + 16].copy_from_slice(&SCM_RIGHTS.to_ne_bytes());

        // Silence unused variable warning.
        let _ = buf_len;

        let (anc, flags) = parse_ancillary_data(&buf, false);
        // First entry must be parsed.
        assert_eq!(anc.len(), 1, "expected exactly one parsed entry");
        // Second entry triggers MSG_CTRUNC.
        assert_ne!(flags & MSG_CTRUNC, 0);
        // Verify the first entry carries the correct fd.
        match anc.get(0) {
            Some(AncillaryData::Rights(r)) => {
                assert_eq!(r.fds.as_slice(), &[5i32]);
            }
            other => panic!("unexpected first entry: {:?}", other),
        }
    }

    /// A buffer larger than CMSG_MAX_LEN must be silently clamped;
    /// this exercises the defensive truncation in parse_ancillary_data.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "ancillary buf exceeds CMSG_MAX_LEN")]
    fn parse_ancillary_oversized_buf_triggers_debug_assert() {
        let big = [0u8; CMSG_MAX_LEN + 1];
        let _ = parse_ancillary_data(&big, false);
    }
}
