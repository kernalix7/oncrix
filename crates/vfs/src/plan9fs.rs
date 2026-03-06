// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Plan 9 (9P2000.L) filesystem protocol implementation.
//!
//! The 9P protocol is a distributed filesystem protocol originating from
//! Plan 9 from Bell Labs. 9P2000.L is the Linux-extended variant that adds
//! Linux-specific semantics (getattr, setattr, lock, etc.).
//!
//! # Architecture
//!
//! ```text
//! VFS operation
//!   → Plan9Session::walk() / open() / read() / write()
//!     → build P9MessageType request + header
//!       → serialize into Plan9Message buffer
//!         → transport layer delivers to 9P server
//!           → parse reply → update FidTable / QidCache
//!             → return result to VFS caller
//! ```
//!
//! # Structures
//!
//! - [`P9MessageType`] — 9P2000.L message type codes (T/R pairs)
//! - [`P9Qid`] — unique file identifier (type, version, path)
//! - [`P9Stat`] — file metadata (9P stat structure)
//! - [`P9Fid`] — file identifier with attached QID and state
//! - [`FidTable`] — FID allocation and tracking table (256 slots)
//! - [`Plan9Message`] — serialization buffer for 9P wire messages
//! - [`Plan9Session`] — 9P client session state machine
//! - [`Plan9Registry`] — global registry of 9P mount points (8 mounts)

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Maximum message size negotiated during Tversion (8 KiB).
const MAX_MESSAGE_SIZE: u32 = 8192;

/// Maximum number of FIDs tracked per session.
const MAX_FIDS: usize = 256;

/// Maximum path component length in bytes.
const MAX_NAME_LEN: usize = 256;

/// Maximum walk elements per Twalk message (9P protocol limit is 16).
const MAX_WALK_ELEMS: usize = 16;

/// Maximum number of 9P mount points.
const MAX_9P_MOUNTS: usize = 8;

/// Maximum mount path length in bytes.
const MAX_MOUNT_PATH: usize = 256;

/// Maximum data payload per read/write (fits within MAX_MESSAGE_SIZE minus headers).
const MAX_IO_SIZE: usize = 7680;

/// 9P2000.L protocol version string length.
const VERSION_STR_LEN: usize = 8;

/// 9P2000.L protocol version string: "9P2000.L".
const P9_VERSION: [u8; VERSION_STR_LEN] = *b"9P2000.L";

/// Wire header size: size(4) + type(1) + tag(2) = 7 bytes.
const HEADER_SIZE: usize = 7;

/// Tag value for version messages (no tag).
const NOTAG: u16 = 0xFFFF;

/// FID value meaning "no FID".
const NOFID: u32 = 0xFFFF_FFFF;

// ── P9MessageType ───────────────────────────────────────────────

/// 9P2000.L protocol message type codes.
///
/// Each operation has a T (transmit/request) and R (receive/response) pair.
/// The response code is always the request code + 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum P9MessageType {
    /// Negotiate protocol version.
    Tversion = 100,
    /// Version negotiation reply.
    Rversion = 101,
    /// Authenticate connection.
    Tauth = 102,
    /// Authentication reply.
    Rauth = 103,
    /// Attach to filesystem root.
    Tattach = 104,
    /// Attach reply.
    Rattach = 105,
    /// Error response (server only).
    Rerror = 107,
    /// Flush pending request.
    Tflush = 108,
    /// Flush reply.
    Rflush = 109,
    /// Walk path elements from a FID.
    Twalk = 110,
    /// Walk reply with QIDs.
    Rwalk = 111,
    /// Open file identified by FID.
    Topen = 112,
    /// Open reply.
    Ropen = 113,
    /// Create file in directory FID.
    Tcreate = 114,
    /// Create reply.
    Rcreate = 115,
    /// Read data from FID.
    Tread = 116,
    /// Read reply.
    Rread = 117,
    /// Write data to FID.
    Twrite = 118,
    /// Write reply.
    Rwrite = 119,
    /// Close (clunk) a FID.
    Tclunk = 120,
    /// Clunk reply.
    Rclunk = 121,
    /// Remove file identified by FID.
    Tremove = 122,
    /// Remove reply.
    Rremove = 123,
    /// Get file attributes.
    Tstat = 124,
    /// Stat reply.
    Rstat = 125,
    /// Set file attributes.
    Twstat = 126,
    /// Wstat reply.
    Rwstat = 127,
}

impl P9MessageType {
    /// Parse a message type from its on-disk byte value.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            100 => Some(Self::Tversion),
            101 => Some(Self::Rversion),
            102 => Some(Self::Tauth),
            103 => Some(Self::Rauth),
            104 => Some(Self::Tattach),
            105 => Some(Self::Rattach),
            107 => Some(Self::Rerror),
            108 => Some(Self::Tflush),
            109 => Some(Self::Rflush),
            110 => Some(Self::Twalk),
            111 => Some(Self::Rwalk),
            112 => Some(Self::Topen),
            113 => Some(Self::Ropen),
            114 => Some(Self::Tcreate),
            115 => Some(Self::Rcreate),
            116 => Some(Self::Tread),
            117 => Some(Self::Rread),
            118 => Some(Self::Twrite),
            119 => Some(Self::Rwrite),
            120 => Some(Self::Tclunk),
            121 => Some(Self::Rclunk),
            122 => Some(Self::Tremove),
            123 => Some(Self::Rremove),
            124 => Some(Self::Tstat),
            125 => Some(Self::Rstat),
            126 => Some(Self::Twstat),
            127 => Some(Self::Rwstat),
            _ => None,
        }
    }

    /// Check if this is a T-message (request from client).
    pub fn is_request(self) -> bool {
        (self as u8) % 2 == 0
    }

    /// Get the expected response type for a T-message.
    ///
    /// Returns `None` if this is already an R-message.
    pub fn response_type(self) -> Option<Self> {
        if self.is_request() {
            Self::from_u8(self as u8 + 1)
        } else {
            None
        }
    }
}

// ── P9QidType ───────────────────────────────────────────────────

/// QID type bits, identifying the nature of a file.
///
/// Multiple bits may be set (e.g., a directory that is also append-only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct P9QidType(pub u8);

impl P9QidType {
    /// Regular file.
    pub const FILE: Self = Self(0x00);
    /// Directory.
    pub const DIR: Self = Self(0x80);
    /// Append-only file.
    pub const APPEND: Self = Self(0x40);
    /// Exclusive-use file.
    pub const EXCL: Self = Self(0x20);
    /// Authentication file.
    pub const AUTH: Self = Self(0x08);
    /// Temporary file.
    pub const TMP: Self = Self(0x04);
    /// Symbolic link (9P2000.L extension).
    pub const SYMLINK: Self = Self(0x02);

    /// Check whether this QID represents a directory.
    pub fn is_dir(self) -> bool {
        self.0 & Self::DIR.0 != 0
    }

    /// Check whether this QID represents a regular file.
    pub fn is_file(self) -> bool {
        self.0 == Self::FILE.0
    }

    /// Check whether this QID represents a symlink.
    pub fn is_symlink(self) -> bool {
        self.0 & Self::SYMLINK.0 != 0
    }
}

// ── P9Qid ───────────────────────────────────────────────────────

/// Unique file identifier on a 9P server.
///
/// Each file on the server has a unique QID consisting of a type byte,
/// a version counter (incremented on modification), and a 64-bit path
/// identifier unique across the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct P9Qid {
    /// QID type bits (directory, file, symlink, etc.).
    pub qtype: P9QidType,
    /// Version number, incremented on each file modification.
    pub version: u32,
    /// Unique path identifier on the server.
    pub path: u64,
}

impl P9Qid {
    /// Size of a QID on the wire: type(1) + version(4) + path(8) = 13 bytes.
    pub const WIRE_SIZE: usize = 13;

    /// Create a new QID.
    pub const fn new(qtype: P9QidType, version: u32, path: u64) -> Self {
        Self {
            qtype,
            version,
            path,
        }
    }

    /// Deserialize a QID from a byte slice at the given offset.
    ///
    /// Returns the parsed QID and the number of bytes consumed.
    pub fn from_bytes(buf: &[u8], offset: usize) -> Result<(Self, usize)> {
        if buf.len() < offset + Self::WIRE_SIZE {
            return Err(Error::InvalidArgument);
        }
        let qtype = P9QidType(buf[offset]);
        let version = u32::from_le_bytes([
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
            buf[offset + 4],
        ]);
        let path = u64::from_le_bytes([
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
            buf[offset + 8],
            buf[offset + 9],
            buf[offset + 10],
            buf[offset + 11],
            buf[offset + 12],
        ]);
        Ok((
            Self {
                qtype,
                version,
                path,
            },
            Self::WIRE_SIZE,
        ))
    }

    /// Serialize this QID into a byte buffer at the given offset.
    ///
    /// Returns the number of bytes written.
    pub fn to_bytes(&self, buf: &mut [u8], offset: usize) -> Result<usize> {
        if buf.len() < offset + Self::WIRE_SIZE {
            return Err(Error::InvalidArgument);
        }
        buf[offset] = self.qtype.0;
        buf[offset + 1..offset + 5].copy_from_slice(&self.version.to_le_bytes());
        buf[offset + 5..offset + 13].copy_from_slice(&self.path.to_le_bytes());
        Ok(Self::WIRE_SIZE)
    }
}

// ── P9Stat ──────────────────────────────────────────────────────

/// File metadata returned by Tstat/Rstat.
///
/// Contains the file's QID, permissions, size, timestamps,
/// owner/group names, and file name.
#[derive(Debug, Clone)]
pub struct P9Stat {
    /// Total size of the stat structure on the wire (excluding this field).
    pub size: u16,
    /// Server-internal type.
    pub dev_type: u16,
    /// Server-internal device identifier.
    pub dev: u32,
    /// Unique identifier for this file.
    pub qid: P9Qid,
    /// Permission and mode bits.
    pub mode: u32,
    /// Last access time (seconds since epoch).
    pub atime: u32,
    /// Last modification time (seconds since epoch).
    pub mtime: u32,
    /// File length in bytes.
    pub length: u64,
    /// File name (without path components).
    pub name: [u8; MAX_NAME_LEN],
    /// Length of the name.
    pub name_len: usize,
    /// Owner user id.
    pub uid: u32,
    /// Owner group id.
    pub gid: u32,
}

impl P9Stat {
    /// Create an empty stat structure.
    pub const fn empty() -> Self {
        Self {
            size: 0,
            dev_type: 0,
            dev: 0,
            qid: P9Qid::new(P9QidType::FILE, 0, 0),
            mode: 0,
            atime: 0,
            mtime: 0,
            length: 0,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            uid: 0,
            gid: 0,
        }
    }

    /// Check whether this stat refers to a directory.
    pub fn is_dir(&self) -> bool {
        self.qid.qtype.is_dir()
    }
}

// ── P9OpenMode ──────────────────────────────────────────────────

/// Open mode flags for Topen requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct P9OpenMode(pub u8);

impl P9OpenMode {
    /// Open for reading.
    pub const OREAD: Self = Self(0);
    /// Open for writing.
    pub const OWRITE: Self = Self(1);
    /// Open for reading and writing.
    pub const ORDWR: Self = Self(2);
    /// Execute (unused in 9P2000.L, but part of protocol).
    pub const OEXEC: Self = Self(3);
    /// Truncate file on open.
    pub const OTRUNC: Self = Self(0x10);
    /// Remove file on clunk.
    pub const ORCLOSE: Self = Self(0x40);

    /// Combine two open mode flags.
    pub const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Check if the mode includes write access.
    pub fn is_writable(self) -> bool {
        let base = self.0 & 0x03;
        base == Self::OWRITE.0 || base == Self::ORDWR.0
    }
}

// ── P9Fid ───────────────────────────────────────────────────────

/// FID state in the 9P protocol.
///
/// A FID is a client-side handle that identifies a file on the server.
/// FIDs are allocated during walk/attach and released on clunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FidState {
    /// FID slot is not in use.
    Free,
    /// FID has been allocated but not yet walked/attached.
    Allocated,
    /// FID is attached to a file (after successful walk or attach).
    Attached,
    /// FID is open for I/O.
    Open,
}

/// A tracked FID in the client session.
///
/// Each FID maps to a file on the 9P server. The client tracks the
/// associated QID, open state, and current I/O offset.
#[derive(Debug, Clone)]
pub struct P9Fid {
    /// Numeric FID value sent on the wire.
    pub fid: u32,
    /// Current state of this FID.
    pub state: FidState,
    /// QID of the file this FID refers to (valid when Attached or Open).
    pub qid: P9Qid,
    /// Open mode (valid only when state is Open).
    pub mode: P9OpenMode,
    /// Current I/O offset for sequential reads/writes.
    pub offset: u64,
    /// Path name associated with this FID (for debugging/display).
    pub path: [u8; MAX_NAME_LEN],
    /// Length of the path name.
    pub path_len: usize,
}

impl P9Fid {
    /// Create a free (unused) FID slot.
    const fn free() -> Self {
        Self {
            fid: 0,
            state: FidState::Free,
            qid: P9Qid::new(P9QidType::FILE, 0, 0),
            mode: P9OpenMode::OREAD,
            offset: 0,
            path: [0; MAX_NAME_LEN],
            path_len: 0,
        }
    }
}

// ── FidTable ────────────────────────────────────────────────────

/// FID allocation and tracking table.
///
/// Manages up to [`MAX_FIDS`] simultaneously active FIDs. Provides
/// allocation, lookup, and release operations. FID numbers are assigned
/// sequentially starting from 1 (0 is reserved for the root FID on
/// initial attach).
pub struct FidTable {
    /// FID slots.
    fids: [P9Fid; MAX_FIDS],
    /// Number of active (non-free) FIDs.
    active_count: usize,
    /// Next FID number to allocate.
    next_fid: u32,
}

impl FidTable {
    /// Create a new, empty FID table.
    pub const fn new() -> Self {
        Self {
            fids: [const { P9Fid::free() }; MAX_FIDS],
            active_count: 0,
            next_fid: 1,
        }
    }

    /// Allocate a new FID, returning the slot index and FID number.
    ///
    /// Returns `OutOfMemory` if the table is full.
    pub fn alloc(&mut self) -> Result<(usize, u32)> {
        let mut slot = None;
        let mut i = 0;
        while i < MAX_FIDS {
            if matches!(self.fids[i].state, FidState::Free) {
                slot = Some(i);
                break;
            }
            i += 1;
        }
        let idx = slot.ok_or(Error::OutOfMemory)?;
        let fid_num = self.next_fid;
        self.next_fid = self.next_fid.wrapping_add(1);
        if self.next_fid == NOFID {
            self.next_fid = 1;
        }
        self.fids[idx].fid = fid_num;
        self.fids[idx].state = FidState::Allocated;
        self.fids[idx].offset = 0;
        self.fids[idx].path_len = 0;
        self.active_count += 1;
        Ok((idx, fid_num))
    }

    /// Look up a FID by its numeric value.
    ///
    /// Returns the slot index if found, or `NotFound`.
    pub fn lookup(&self, fid: u32) -> Result<usize> {
        let mut i = 0;
        while i < MAX_FIDS {
            if !matches!(self.fids[i].state, FidState::Free) && self.fids[i].fid == fid {
                return Ok(i);
            }
            i += 1;
        }
        Err(Error::NotFound)
    }

    /// Get a reference to the FID entry at the given slot.
    pub fn get(&self, slot: usize) -> Result<&P9Fid> {
        if slot >= MAX_FIDS {
            return Err(Error::InvalidArgument);
        }
        if matches!(self.fids[slot].state, FidState::Free) {
            return Err(Error::NotFound);
        }
        Ok(&self.fids[slot])
    }

    /// Get a mutable reference to the FID entry at the given slot.
    pub fn get_mut(&mut self, slot: usize) -> Result<&mut P9Fid> {
        if slot >= MAX_FIDS {
            return Err(Error::InvalidArgument);
        }
        if matches!(self.fids[slot].state, FidState::Free) {
            return Err(Error::NotFound);
        }
        Ok(&mut self.fids[slot])
    }

    /// Release (clunk) a FID, freeing its slot.
    pub fn release(&mut self, fid: u32) -> Result<()> {
        let idx = self.lookup(fid)?;
        self.fids[idx].state = FidState::Free;
        self.fids[idx].fid = 0;
        self.fids[idx].qid = P9Qid::new(P9QidType::FILE, 0, 0);
        self.fids[idx].offset = 0;
        self.fids[idx].path_len = 0;
        self.active_count = self.active_count.saturating_sub(1);
        Ok(())
    }

    /// Return the number of active FIDs.
    pub fn active_count(&self) -> usize {
        self.active_count
    }
}

// ── Plan9Message ────────────────────────────────────────────────

/// Serialization buffer for 9P wire messages.
///
/// Messages have the format: `size[4] type[1] tag[2] payload[...]`
/// where `size` includes itself.
pub struct Plan9Message {
    /// Wire-format buffer.
    buf: [u8; MAX_MESSAGE_SIZE as usize],
    /// Current write position in the buffer.
    pos: usize,
}

impl Plan9Message {
    /// Create a new empty message.
    pub const fn new() -> Self {
        Self {
            buf: [0; MAX_MESSAGE_SIZE as usize],
            pos: HEADER_SIZE,
        }
    }

    /// Reset the message for building a new request.
    pub fn reset(&mut self, msg_type: P9MessageType, tag: u16) {
        self.buf = [0; MAX_MESSAGE_SIZE as usize];
        self.pos = HEADER_SIZE;
        // Type byte at offset 4.
        self.buf[4] = msg_type as u8;
        // Tag at offset 5..7.
        self.buf[5] = tag as u8;
        self.buf[6] = (tag >> 8) as u8;
    }

    /// Append a u8 value to the message payload.
    pub fn put_u8(&mut self, v: u8) -> Result<()> {
        if self.pos + 1 > self.buf.len() {
            return Err(Error::InvalidArgument);
        }
        self.buf[self.pos] = v;
        self.pos += 1;
        Ok(())
    }

    /// Append a u16 (little-endian) to the message payload.
    pub fn put_u16(&mut self, v: u16) -> Result<()> {
        if self.pos + 2 > self.buf.len() {
            return Err(Error::InvalidArgument);
        }
        self.buf[self.pos..self.pos + 2].copy_from_slice(&v.to_le_bytes());
        self.pos += 2;
        Ok(())
    }

    /// Append a u32 (little-endian) to the message payload.
    pub fn put_u32(&mut self, v: u32) -> Result<()> {
        if self.pos + 4 > self.buf.len() {
            return Err(Error::InvalidArgument);
        }
        self.buf[self.pos..self.pos + 4].copy_from_slice(&v.to_le_bytes());
        self.pos += 4;
        Ok(())
    }

    /// Append a u64 (little-endian) to the message payload.
    pub fn put_u64(&mut self, v: u64) -> Result<()> {
        if self.pos + 8 > self.buf.len() {
            return Err(Error::InvalidArgument);
        }
        self.buf[self.pos..self.pos + 8].copy_from_slice(&v.to_le_bytes());
        self.pos += 8;
        Ok(())
    }

    /// Append a length-prefixed string (u16 length + bytes).
    pub fn put_string(&mut self, s: &[u8]) -> Result<()> {
        let len = s.len();
        if len > u16::MAX as usize {
            return Err(Error::InvalidArgument);
        }
        self.put_u16(len as u16)?;
        if self.pos + len > self.buf.len() {
            return Err(Error::InvalidArgument);
        }
        self.buf[self.pos..self.pos + len].copy_from_slice(s);
        self.pos += len;
        Ok(())
    }

    /// Append raw data bytes.
    pub fn put_data(&mut self, data: &[u8]) -> Result<()> {
        if self.pos + data.len() > self.buf.len() {
            return Err(Error::InvalidArgument);
        }
        self.buf[self.pos..self.pos + data.len()].copy_from_slice(data);
        self.pos += data.len();
        Ok(())
    }

    /// Finalize the message by writing the total size in the header.
    ///
    /// Returns a reference to the complete wire message.
    pub fn finalize(&mut self) -> &[u8] {
        let size = self.pos as u32;
        self.buf[0..4].copy_from_slice(&size.to_le_bytes());
        &self.buf[..self.pos]
    }

    /// Parse the header from a received message.
    ///
    /// Returns (message_type, tag, payload_start_offset).
    pub fn parse_header(buf: &[u8]) -> Result<(P9MessageType, u16, usize)> {
        if buf.len() < HEADER_SIZE {
            return Err(Error::InvalidArgument);
        }
        let _size = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let msg_type = P9MessageType::from_u8(buf[4]).ok_or(Error::InvalidArgument)?;
        let tag = u16::from_le_bytes([buf[5], buf[6]]);
        Ok((msg_type, tag, HEADER_SIZE))
    }

    /// Read a u32 from a buffer at the given offset.
    pub fn read_u32(buf: &[u8], offset: usize) -> Result<(u32, usize)> {
        if buf.len() < offset + 4 {
            return Err(Error::InvalidArgument);
        }
        let v = u32::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]);
        Ok((v, offset + 4))
    }

    /// Read a u64 from a buffer at the given offset.
    pub fn read_u64(buf: &[u8], offset: usize) -> Result<(u64, usize)> {
        if buf.len() < offset + 8 {
            return Err(Error::InvalidArgument);
        }
        let v = u64::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]);
        Ok((v, offset + 8))
    }

    /// Read a length-prefixed string from a buffer at the given offset.
    ///
    /// Returns (byte slice, next offset). The slice borrows from `buf`.
    pub fn read_string(buf: &[u8], offset: usize) -> Result<(&[u8], usize)> {
        if buf.len() < offset + 2 {
            return Err(Error::InvalidArgument);
        }
        let len = u16::from_le_bytes([buf[offset], buf[offset + 1]]) as usize;
        let start = offset + 2;
        if buf.len() < start + len {
            return Err(Error::InvalidArgument);
        }
        Ok((&buf[start..start + len], start + len))
    }
}

// ── SessionState ────────────────────────────────────────────────

/// 9P session state machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Session is not connected.
    Disconnected,
    /// Version negotiation in progress.
    Negotiating,
    /// Version agreed, ready to authenticate/attach.
    Versioned,
    /// Authentication in progress.
    Authenticating,
    /// Attached to filesystem root, ready for I/O.
    Attached,
    /// Session has encountered an error.
    Error,
}

// ── Plan9Session ────────────────────────────────────────────────

/// 9P2000.L client session.
///
/// Manages the lifecycle of a 9P connection: version negotiation,
/// authentication, filesystem attach, and file operations.
pub struct Plan9Session {
    /// Current session state.
    state: SessionState,
    /// Negotiated maximum message size.
    msize: u32,
    /// FID table for this session.
    fid_table: FidTable,
    /// FID of the filesystem root (set after attach).
    root_fid: u32,
    /// Next tag number for request/response matching.
    next_tag: u16,
    /// Message serialization buffer.
    msg_buf: Plan9Message,
    /// User ID for authentication.
    uid: u32,
    /// Mount path for this session.
    mount_path: [u8; MAX_MOUNT_PATH],
    /// Length of the mount path.
    mount_path_len: usize,
}

impl Plan9Session {
    /// Create a new disconnected session.
    pub const fn new() -> Self {
        Self {
            state: SessionState::Disconnected,
            msize: MAX_MESSAGE_SIZE,
            fid_table: FidTable::new(),
            root_fid: NOFID,
            next_tag: 1,
            msg_buf: Plan9Message::new(),
            uid: 0,
            mount_path: [0; MAX_MOUNT_PATH],
            mount_path_len: 0,
        }
    }

    /// Get the current session state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Get the negotiated maximum message size.
    pub fn msize(&self) -> u32 {
        self.msize
    }

    /// Allocate the next tag for a request.
    fn alloc_tag(&mut self) -> u16 {
        let tag = self.next_tag;
        self.next_tag = self.next_tag.wrapping_add(1);
        if self.next_tag == NOTAG {
            self.next_tag = 1;
        }
        tag
    }

    /// Build a Tversion message to initiate protocol negotiation.
    ///
    /// The caller must send the returned bytes to the server and call
    /// [`handle_rversion`](Self::handle_rversion) with the reply.
    pub fn build_tversion(&mut self) -> Result<&[u8]> {
        self.state = SessionState::Negotiating;
        self.msg_buf.reset(P9MessageType::Tversion, NOTAG);
        self.msg_buf.put_u32(self.msize)?;
        self.msg_buf.put_string(&P9_VERSION)?;
        Ok(self.msg_buf.finalize())
    }

    /// Handle an Rversion reply from the server.
    ///
    /// Updates the negotiated message size and transitions to Versioned state.
    pub fn handle_rversion(&mut self, reply: &[u8]) -> Result<()> {
        let (msg_type, _tag, offset) = Plan9Message::parse_header(reply)?;
        if msg_type != P9MessageType::Rversion {
            self.state = SessionState::Error;
            return Err(Error::IoError);
        }
        let (server_msize, offset) = Plan9Message::read_u32(reply, offset)?;
        let (version_str, _offset) = Plan9Message::read_string(reply, offset)?;
        // Verify version string matches.
        if version_str.len() != VERSION_STR_LEN {
            self.state = SessionState::Error;
            return Err(Error::InvalidArgument);
        }
        let mut matches = true;
        let mut i = 0;
        while i < VERSION_STR_LEN {
            if version_str[i] != P9_VERSION[i] {
                matches = false;
                break;
            }
            i += 1;
        }
        if !matches {
            self.state = SessionState::Error;
            return Err(Error::InvalidArgument);
        }
        // Use the smaller of client/server msize.
        if server_msize < self.msize {
            self.msize = server_msize;
        }
        self.state = SessionState::Versioned;
        Ok(())
    }

    /// Build a Tattach message to attach to the filesystem root.
    ///
    /// `aname` is the filesystem name on the server to attach to.
    pub fn build_tattach(&mut self, uid: u32, aname: &[u8]) -> Result<&[u8]> {
        if self.state != SessionState::Versioned {
            return Err(Error::InvalidArgument);
        }
        self.uid = uid;
        let (slot, fid_num) = self.fid_table.alloc()?;
        let tag = self.alloc_tag();
        self.msg_buf.reset(P9MessageType::Tattach, tag);
        self.msg_buf.put_u32(fid_num)?;
        self.msg_buf.put_u32(NOFID)?; // afid (no auth)
        // uname
        self.msg_buf.put_string(b"")?;
        // aname
        self.msg_buf.put_string(aname)?;
        // n_uname (9P2000.L extension: numeric uid)
        self.msg_buf.put_u32(uid)?;
        self.root_fid = fid_num;
        let fid_entry = self.fid_table.get_mut(slot)?;
        fid_entry.state = FidState::Attached;
        Ok(self.msg_buf.finalize())
    }

    /// Handle an Rattach reply from the server.
    pub fn handle_rattach(&mut self, reply: &[u8]) -> Result<P9Qid> {
        let (msg_type, _tag, offset) = Plan9Message::parse_header(reply)?;
        if msg_type == P9MessageType::Rerror {
            self.state = SessionState::Error;
            return Err(Error::IoError);
        }
        if msg_type != P9MessageType::Rattach {
            self.state = SessionState::Error;
            return Err(Error::InvalidArgument);
        }
        let (qid, _) = P9Qid::from_bytes(reply, offset)?;
        // Update root FID with the server's QID.
        let slot = self.fid_table.lookup(self.root_fid)?;
        let fid_entry = self.fid_table.get_mut(slot)?;
        fid_entry.qid = qid;
        self.state = SessionState::Attached;
        Ok(qid)
    }

    /// Build a Twalk message to walk path elements from a source FID.
    ///
    /// `src_fid` is an existing attached FID. `names` are the path components
    /// to walk. A new FID is allocated for the walk destination.
    ///
    /// Returns the wire message and the newly allocated destination FID number.
    pub fn build_twalk(&mut self, src_fid: u32, names: &[&[u8]]) -> Result<(&[u8], u32)> {
        if self.state != SessionState::Attached {
            return Err(Error::InvalidArgument);
        }
        if names.len() > MAX_WALK_ELEMS {
            return Err(Error::InvalidArgument);
        }
        // Verify src_fid exists.
        let _src_slot = self.fid_table.lookup(src_fid)?;
        let (_dst_slot, dst_fid) = self.fid_table.alloc()?;
        let tag = self.alloc_tag();
        self.msg_buf.reset(P9MessageType::Twalk, tag);
        self.msg_buf.put_u32(src_fid)?;
        self.msg_buf.put_u32(dst_fid)?;
        self.msg_buf.put_u16(names.len() as u16)?;
        let mut i = 0;
        while i < names.len() {
            self.msg_buf.put_string(names[i])?;
            i += 1;
        }
        Ok((self.msg_buf.finalize(), dst_fid))
    }

    /// Handle an Rwalk reply from the server.
    ///
    /// Returns the array of QIDs for each successfully walked element.
    pub fn handle_rwalk(
        &mut self,
        reply: &[u8],
        dst_fid: u32,
    ) -> Result<(usize, [P9Qid; MAX_WALK_ELEMS])> {
        let (msg_type, _tag, mut offset) = Plan9Message::parse_header(reply)?;
        if msg_type == P9MessageType::Rerror {
            // Walk failed — release the destination FID.
            let _ = self.fid_table.release(dst_fid);
            return Err(Error::NotFound);
        }
        if msg_type != P9MessageType::Rwalk {
            let _ = self.fid_table.release(dst_fid);
            return Err(Error::InvalidArgument);
        }
        if reply.len() < offset + 2 {
            let _ = self.fid_table.release(dst_fid);
            return Err(Error::InvalidArgument);
        }
        let nwqid = u16::from_le_bytes([reply[offset], reply[offset + 1]]) as usize;
        offset += 2;
        if nwqid > MAX_WALK_ELEMS {
            let _ = self.fid_table.release(dst_fid);
            return Err(Error::InvalidArgument);
        }
        let mut qids = [P9Qid::new(P9QidType::FILE, 0, 0); MAX_WALK_ELEMS];
        let mut i = 0;
        while i < nwqid {
            let (qid, consumed) = P9Qid::from_bytes(reply, offset)?;
            qids[i] = qid;
            offset += consumed;
            i += 1;
        }
        // Update the destination FID with the final QID.
        if nwqid > 0 {
            let slot = self.fid_table.lookup(dst_fid)?;
            let fid_entry = self.fid_table.get_mut(slot)?;
            fid_entry.state = FidState::Attached;
            fid_entry.qid = qids[nwqid - 1];
        }
        Ok((nwqid, qids))
    }

    /// Build a Topen message to open a file identified by FID.
    pub fn build_topen(&mut self, fid: u32, mode: P9OpenMode) -> Result<&[u8]> {
        if self.state != SessionState::Attached {
            return Err(Error::InvalidArgument);
        }
        let _slot = self.fid_table.lookup(fid)?;
        let tag = self.alloc_tag();
        self.msg_buf.reset(P9MessageType::Topen, tag);
        self.msg_buf.put_u32(fid)?;
        self.msg_buf.put_u8(mode.0)?;
        Ok(self.msg_buf.finalize())
    }

    /// Handle an Ropen reply.
    ///
    /// Returns the QID and iounit (maximum I/O size for this open file).
    pub fn handle_ropen(
        &mut self,
        reply: &[u8],
        fid: u32,
        mode: P9OpenMode,
    ) -> Result<(P9Qid, u32)> {
        let (msg_type, _tag, offset) = Plan9Message::parse_header(reply)?;
        if msg_type == P9MessageType::Rerror {
            return Err(Error::PermissionDenied);
        }
        if msg_type != P9MessageType::Ropen {
            return Err(Error::InvalidArgument);
        }
        let (qid, qid_end) = P9Qid::from_bytes(reply, offset)?;
        let (iounit, _) = Plan9Message::read_u32(reply, offset + qid_end)?;
        let slot = self.fid_table.lookup(fid)?;
        let fid_entry = self.fid_table.get_mut(slot)?;
        fid_entry.state = FidState::Open;
        fid_entry.qid = qid;
        fid_entry.mode = mode;
        fid_entry.offset = 0;
        Ok((qid, iounit))
    }

    /// Build a Tread message to read data from an open FID.
    pub fn build_tread(&mut self, fid: u32, offset: u64, count: u32) -> Result<&[u8]> {
        if self.state != SessionState::Attached {
            return Err(Error::InvalidArgument);
        }
        let slot = self.fid_table.lookup(fid)?;
        let fid_entry = self.fid_table.get(slot)?;
        if fid_entry.state != FidState::Open {
            return Err(Error::InvalidArgument);
        }
        let clamped = if count as usize > MAX_IO_SIZE {
            MAX_IO_SIZE as u32
        } else {
            count
        };
        let tag = self.alloc_tag();
        self.msg_buf.reset(P9MessageType::Tread, tag);
        self.msg_buf.put_u32(fid)?;
        self.msg_buf.put_u64(offset)?;
        self.msg_buf.put_u32(clamped)?;
        Ok(self.msg_buf.finalize())
    }

    /// Build a Twrite message to write data to an open FID.
    pub fn build_twrite(&mut self, fid: u32, offset: u64, data: &[u8]) -> Result<&[u8]> {
        if self.state != SessionState::Attached {
            return Err(Error::InvalidArgument);
        }
        let slot = self.fid_table.lookup(fid)?;
        let fid_entry = self.fid_table.get(slot)?;
        if fid_entry.state != FidState::Open {
            return Err(Error::InvalidArgument);
        }
        if !fid_entry.mode.is_writable() {
            return Err(Error::PermissionDenied);
        }
        let len = if data.len() > MAX_IO_SIZE {
            MAX_IO_SIZE
        } else {
            data.len()
        };
        let tag = self.alloc_tag();
        self.msg_buf.reset(P9MessageType::Twrite, tag);
        self.msg_buf.put_u32(fid)?;
        self.msg_buf.put_u64(offset)?;
        self.msg_buf.put_u32(len as u32)?;
        self.msg_buf.put_data(&data[..len])?;
        Ok(self.msg_buf.finalize())
    }

    /// Build a Tclunk message to release a FID.
    pub fn build_tclunk(&mut self, fid: u32) -> Result<&[u8]> {
        let _slot = self.fid_table.lookup(fid)?;
        let tag = self.alloc_tag();
        self.msg_buf.reset(P9MessageType::Tclunk, tag);
        self.msg_buf.put_u32(fid)?;
        Ok(self.msg_buf.finalize())
    }

    /// Handle an Rclunk reply and release the FID.
    pub fn handle_rclunk(&mut self, reply: &[u8], fid: u32) -> Result<()> {
        let (msg_type, _tag, _offset) = Plan9Message::parse_header(reply)?;
        if msg_type == P9MessageType::Rerror {
            return Err(Error::IoError);
        }
        if msg_type != P9MessageType::Rclunk {
            return Err(Error::InvalidArgument);
        }
        self.fid_table.release(fid)
    }

    /// Build a Tremove message to delete a file and release the FID.
    pub fn build_tremove(&mut self, fid: u32) -> Result<&[u8]> {
        let _slot = self.fid_table.lookup(fid)?;
        let tag = self.alloc_tag();
        self.msg_buf.reset(P9MessageType::Tremove, tag);
        self.msg_buf.put_u32(fid)?;
        Ok(self.msg_buf.finalize())
    }

    /// Build a Tstat message to retrieve file attributes.
    pub fn build_tstat(&mut self, fid: u32) -> Result<&[u8]> {
        let _slot = self.fid_table.lookup(fid)?;
        let tag = self.alloc_tag();
        self.msg_buf.reset(P9MessageType::Tstat, tag);
        self.msg_buf.put_u32(fid)?;
        Ok(self.msg_buf.finalize())
    }

    /// Get the root FID for this session.
    pub fn root_fid(&self) -> u32 {
        self.root_fid
    }

    /// Access the FID table.
    pub fn fid_table(&self) -> &FidTable {
        &self.fid_table
    }

    /// Set the mount path for this session.
    pub fn set_mount_path(&mut self, path: &[u8]) -> Result<()> {
        if path.len() > MAX_MOUNT_PATH {
            return Err(Error::InvalidArgument);
        }
        self.mount_path[..path.len()].copy_from_slice(path);
        self.mount_path_len = path.len();
        Ok(())
    }
}

// ── FdToFidMap ──────────────────────────────────────────────────

/// Mapping from VFS file descriptor numbers to 9P FID numbers.
///
/// The VFS layer uses integer file descriptors (fd), while 9P uses
/// FIDs. This table provides the translation.
pub struct FdToFidMap {
    /// Entries mapping fd → fid. Entry is valid when fid != NOFID.
    entries: [(i32, u32); MAX_FIDS],
    /// Number of active mappings.
    count: usize,
}

impl FdToFidMap {
    /// Create a new, empty mapping.
    pub const fn new() -> Self {
        Self {
            entries: [(-1, NOFID); MAX_FIDS],
            count: 0,
        }
    }

    /// Insert a mapping from fd to fid.
    pub fn insert(&mut self, fd: i32, fid: u32) -> Result<()> {
        // Check for duplicate fd.
        let mut i = 0;
        while i < MAX_FIDS {
            if self.entries[i].0 == fd && self.entries[i].1 != NOFID {
                return Err(Error::AlreadyExists);
            }
            i += 1;
        }
        // Find a free slot.
        i = 0;
        while i < MAX_FIDS {
            if self.entries[i].1 == NOFID {
                self.entries[i] = (fd, fid);
                self.count += 1;
                return Ok(());
            }
            i += 1;
        }
        Err(Error::OutOfMemory)
    }

    /// Look up the FID for a given file descriptor.
    pub fn lookup(&self, fd: i32) -> Result<u32> {
        let mut i = 0;
        while i < MAX_FIDS {
            if self.entries[i].0 == fd && self.entries[i].1 != NOFID {
                return Ok(self.entries[i].1);
            }
            i += 1;
        }
        Err(Error::NotFound)
    }

    /// Remove a mapping by file descriptor.
    pub fn remove(&mut self, fd: i32) -> Result<u32> {
        let mut i = 0;
        while i < MAX_FIDS {
            if self.entries[i].0 == fd && self.entries[i].1 != NOFID {
                let fid = self.entries[i].1;
                self.entries[i] = (-1, NOFID);
                self.count = self.count.saturating_sub(1);
                return Ok(fid);
            }
            i += 1;
        }
        Err(Error::NotFound)
    }

    /// Get the number of active mappings.
    pub fn count(&self) -> usize {
        self.count
    }
}

// ── Plan9Registry ───────────────────────────────────────────────

/// Global registry of 9P mount points.
///
/// Tracks up to [`MAX_9P_MOUNTS`] active 9P mounts. Each mount has
/// a path and an associated session.
pub struct Plan9Registry {
    /// Mount paths.
    paths: [[u8; MAX_MOUNT_PATH]; MAX_9P_MOUNTS],
    /// Path lengths.
    path_lens: [usize; MAX_9P_MOUNTS],
    /// Whether each slot is in use.
    active: [bool; MAX_9P_MOUNTS],
    /// Number of active mounts.
    count: usize,
}

impl Plan9Registry {
    /// Create a new, empty registry.
    pub const fn new() -> Self {
        Self {
            paths: [[0; MAX_MOUNT_PATH]; MAX_9P_MOUNTS],
            path_lens: [0; MAX_9P_MOUNTS],
            active: [false; MAX_9P_MOUNTS],
            count: 0,
        }
    }

    /// Register a new mount point.
    ///
    /// Returns the slot index.
    pub fn mount(&mut self, path: &[u8]) -> Result<usize> {
        if path.len() > MAX_MOUNT_PATH {
            return Err(Error::InvalidArgument);
        }
        // Check for duplicate.
        let mut i = 0;
        while i < MAX_9P_MOUNTS {
            if self.active[i]
                && self.path_lens[i] == path.len()
                && self.paths[i][..path.len()] == *path
            {
                return Err(Error::AlreadyExists);
            }
            i += 1;
        }
        // Find a free slot.
        i = 0;
        while i < MAX_9P_MOUNTS {
            if !self.active[i] {
                self.paths[i][..path.len()].copy_from_slice(path);
                self.path_lens[i] = path.len();
                self.active[i] = true;
                self.count += 1;
                return Ok(i);
            }
            i += 1;
        }
        Err(Error::OutOfMemory)
    }

    /// Unmount a 9P mount by slot index.
    pub fn unmount(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_9P_MOUNTS || !self.active[slot] {
            return Err(Error::NotFound);
        }
        self.active[slot] = false;
        self.path_lens[slot] = 0;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Look up a mount by path, returning the slot index if found.
    pub fn lookup(&self, path: &[u8]) -> Result<usize> {
        let mut i = 0;
        while i < MAX_9P_MOUNTS {
            if self.active[i]
                && self.path_lens[i] == path.len()
                && self.paths[i][..path.len()] == *path
            {
                return Ok(i);
            }
            i += 1;
        }
        Err(Error::NotFound)
    }

    /// Return the number of active mounts.
    pub fn count(&self) -> usize {
        self.count
    }
}
