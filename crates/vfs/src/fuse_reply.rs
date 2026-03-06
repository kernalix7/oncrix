// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! FUSE reply handling.
//!
//! Encodes reply messages sent from the FUSE kernel module back to the
//! user-space daemon via `/dev/fuse`. Each reply begins with a fixed
//! [`FuseOutHeader`] containing the error code and unique request ID,
//! followed by an optional payload.
//!
//! # Design
//!
//! - [`FuseOutHeader`] — common reply header (error, unique, length)
//! - [`FuseEntryOut`] — reply payload for LOOKUP/MKNOD/MKDIR/SYMLINK/LINK
//! - [`FuseAttrOut`] — reply payload for GETATTR/SETATTR
//! - [`FuseReplyBuf`] — assembled reply with header + payload
//! - Helpers: `fuse_reply_err`, `fuse_reply_entry`, `fuse_reply_attr`,
//!   `fuse_reply_data`
//!
//! # References
//!
//! - Linux `include/uapi/linux/fuse.h`
//! - `libfuse/lib/fuse_lowlevel.c`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum payload size in a single reply buffer.
const FUSE_REPLY_BUF_SIZE: usize = 4096;

/// FUSE attribute timeout: 1 second (in nanosecond resolution).
const FUSE_DEFAULT_ATTR_TIMEOUT_NS: u64 = 1_000_000_000;

/// FUSE entry timeout: 1 second.
const FUSE_DEFAULT_ENTRY_TIMEOUT_NS: u64 = 1_000_000_000;

/// Maximum pending requests before timeout-based abort kicks in.
const MAX_PENDING_REQUESTS: usize = 32;

/// Deadline granularity (abstract time units).
const REQUEST_TIMEOUT: u64 = 60_000;

// ---------------------------------------------------------------------------
// FUSE on-wire structures
// ---------------------------------------------------------------------------

/// Common header for every FUSE reply sent to the daemon.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FuseOutHeader {
    /// Total length of the reply (header + payload).
    pub len: u32,
    /// Negative errno on error (0 = success).
    pub error: i32,
    /// Matches the `unique` field of the original request.
    pub unique: u64,
}

impl FuseOutHeader {
    /// Create a success header for the given request unique ID.
    pub const fn ok(unique: u64, payload_len: u32) -> Self {
        Self {
            len: core::mem::size_of::<FuseOutHeader>() as u32 + payload_len,
            error: 0,
            unique,
        }
    }

    /// Create an error header (payload_len = 0).
    pub const fn err(unique: u64, errno: i32) -> Self {
        Self {
            len: core::mem::size_of::<FuseOutHeader>() as u32,
            error: -errno.abs(),
            unique,
        }
    }
}

/// FUSE file attribute structure (matches `struct fuse_attr`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FuseAttr {
    /// Inode number.
    pub ino: u64,
    /// File size.
    pub size: u64,
    /// Allocated blocks (512-byte units).
    pub blocks: u64,
    /// Access time (seconds).
    pub atime: u64,
    /// Modification time (seconds).
    pub mtime: u64,
    /// Change time (seconds).
    pub ctime: u64,
    /// Access time nanoseconds.
    pub atimensec: u32,
    /// Modification time nanoseconds.
    pub mtimensec: u32,
    /// Change time nanoseconds.
    pub ctimensec: u32,
    /// Mode and file type bits.
    pub mode: u32,
    /// Number of hard links.
    pub nlink: u32,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Device ID (for special files).
    pub rdev: u32,
    /// Block size for I/O.
    pub blksize: u32,
    /// Padding.
    pub padding: u32,
}

/// Reply payload for LOOKUP, MKNOD, MKDIR, SYMLINK, LINK operations.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FuseEntryOut {
    /// Nodeid assigned to this dentry.
    pub nodeid: u64,
    /// Generation number for this nodeid.
    pub entry_generation: u64,
    /// Entry validity timeout (seconds).
    pub entry_valid: u64,
    /// Attribute validity timeout (seconds).
    pub attr_valid: u64,
    /// Entry validity timeout (nanoseconds).
    pub entry_valid_nsec: u32,
    /// Attribute validity timeout (nanoseconds).
    pub attr_valid_nsec: u32,
    /// File attributes.
    pub attr: FuseAttr,
}

/// Reply payload for GETATTR / SETATTR.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FuseAttrOut {
    /// Attribute validity timeout (seconds).
    pub attr_valid: u64,
    /// Attribute validity timeout (nanoseconds).
    pub attr_valid_nsec: u32,
    /// Padding.
    pub dummy: u32,
    /// File attributes.
    pub attr: FuseAttr,
}

// ---------------------------------------------------------------------------
// FuseReplyBuf
// ---------------------------------------------------------------------------

/// An assembled FUSE reply message: header + payload.
pub struct FuseReplyBuf {
    /// Raw bytes (header immediately followed by payload).
    buf: [u8; FUSE_REPLY_BUF_SIZE],
    /// Total valid bytes in `buf`.
    len: usize,
}

impl FuseReplyBuf {
    /// Create an empty reply buffer.
    pub const fn new() -> Self {
        Self {
            buf: [0u8; FUSE_REPLY_BUF_SIZE],
            len: 0,
        }
    }

    /// Return the assembled reply bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Return the total reply length.
    pub fn reply_len(&self) -> usize {
        self.len
    }

    /// Copy `src` bytes starting at `offset` into `buf`.
    fn write_bytes(&mut self, offset: usize, src: &[u8]) -> Result<()> {
        if offset + src.len() > FUSE_REPLY_BUF_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.buf[offset..offset + src.len()].copy_from_slice(src);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Reply helpers
// ---------------------------------------------------------------------------

/// Write an error-only reply for the request `unique` with errno `err`.
///
/// The `err` value should be a positive POSIX errno (e.g., `ENOENT = 2`).
pub fn fuse_reply_err(reply: &mut FuseReplyBuf, unique: u64, err: i32) -> Result<()> {
    let hdr = FuseOutHeader::err(unique, err);
    let hdr_bytes = header_as_bytes(&hdr);
    reply.write_bytes(0, hdr_bytes)?;
    reply.len = core::mem::size_of::<FuseOutHeader>();
    Ok(())
}

/// Write a LOOKUP/MKNOD/MKDIR entry reply.
///
/// Fills in default timeouts from `FUSE_DEFAULT_ENTRY_TIMEOUT_NS` and
/// `FUSE_DEFAULT_ATTR_TIMEOUT_NS`.
pub fn fuse_reply_entry(
    reply: &mut FuseReplyBuf,
    unique: u64,
    mut entry: FuseEntryOut,
) -> Result<()> {
    if entry.entry_valid == 0 && entry.entry_valid_nsec == 0 {
        entry.entry_valid = FUSE_DEFAULT_ENTRY_TIMEOUT_NS / 1_000_000_000;
        entry.entry_valid_nsec = (FUSE_DEFAULT_ENTRY_TIMEOUT_NS % 1_000_000_000) as u32;
    }
    if entry.attr_valid == 0 && entry.attr_valid_nsec == 0 {
        entry.attr_valid = FUSE_DEFAULT_ATTR_TIMEOUT_NS / 1_000_000_000;
        entry.attr_valid_nsec = (FUSE_DEFAULT_ATTR_TIMEOUT_NS % 1_000_000_000) as u32;
    }
    let payload_bytes = entry_out_as_bytes(&entry);
    let hdr = FuseOutHeader::ok(unique, payload_bytes.len() as u32);
    let hdr_bytes = header_as_bytes(&hdr);

    reply.write_bytes(0, hdr_bytes)?;
    reply.write_bytes(hdr_bytes.len(), payload_bytes)?;
    reply.len = hdr_bytes.len() + payload_bytes.len();
    Ok(())
}

/// Write a GETATTR/SETATTR attribute reply.
pub fn fuse_reply_attr(
    reply: &mut FuseReplyBuf,
    unique: u64,
    mut attr_out: FuseAttrOut,
) -> Result<()> {
    if attr_out.attr_valid == 0 && attr_out.attr_valid_nsec == 0 {
        attr_out.attr_valid = FUSE_DEFAULT_ATTR_TIMEOUT_NS / 1_000_000_000;
        attr_out.attr_valid_nsec = (FUSE_DEFAULT_ATTR_TIMEOUT_NS % 1_000_000_000) as u32;
    }
    let payload_bytes = attr_out_as_bytes(&attr_out);
    let hdr = FuseOutHeader::ok(unique, payload_bytes.len() as u32);
    let hdr_bytes = header_as_bytes(&hdr);

    reply.write_bytes(0, hdr_bytes)?;
    reply.write_bytes(hdr_bytes.len(), payload_bytes)?;
    reply.len = hdr_bytes.len() + payload_bytes.len();
    Ok(())
}

/// Write a READ data reply with raw bytes.
///
/// `data.len()` must be ≤ `FUSE_REPLY_BUF_SIZE - sizeof(FuseOutHeader)`.
pub fn fuse_reply_data(reply: &mut FuseReplyBuf, unique: u64, data: &[u8]) -> Result<()> {
    let hdr = FuseOutHeader::ok(unique, data.len() as u32);
    let hdr_bytes = header_as_bytes(&hdr);
    if hdr_bytes.len() + data.len() > FUSE_REPLY_BUF_SIZE {
        return Err(Error::InvalidArgument);
    }
    reply.write_bytes(0, hdr_bytes)?;
    reply.write_bytes(hdr_bytes.len(), data)?;
    reply.len = hdr_bytes.len() + data.len();
    Ok(())
}

// ---------------------------------------------------------------------------
// Pending request table with timeout-based abort
// ---------------------------------------------------------------------------

/// Tracks an outstanding FUSE request.
#[derive(Clone, Copy, Debug)]
pub struct PendingRequest {
    /// Request unique ID.
    pub unique: u64,
    /// Abstract timestamp when the request was submitted.
    pub submitted_at: u64,
    /// Operation code.
    pub opcode: u32,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl PendingRequest {
    const fn empty() -> Self {
        Self {
            unique: 0,
            submitted_at: 0,
            opcode: 0,
            active: false,
        }
    }
}

/// Table of outstanding FUSE requests.
pub struct PendingRequestTable {
    entries: [PendingRequest; MAX_PENDING_REQUESTS],
}

impl PendingRequestTable {
    /// Create an empty pending request table.
    pub const fn new() -> Self {
        Self {
            entries: [const { PendingRequest::empty() }; MAX_PENDING_REQUESTS],
        }
    }

    /// Register a new pending request.
    ///
    /// Returns `Err(OutOfMemory)` if the table is full.
    pub fn register(&mut self, unique: u64, opcode: u32, now: u64) -> Result<()> {
        let slot = self
            .entries
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;
        self.entries[slot] = PendingRequest {
            unique,
            submitted_at: now,
            opcode,
            active: true,
        };
        Ok(())
    }

    /// Complete (remove) the request with `unique`.
    ///
    /// Returns `Err(NotFound)` if not found.
    pub fn complete(&mut self, unique: u64) -> Result<()> {
        let slot = self
            .entries
            .iter()
            .position(|e| e.active && e.unique == unique)
            .ok_or(Error::NotFound)?;
        self.entries[slot] = PendingRequest::empty();
        Ok(())
    }

    /// Abort all requests that have exceeded `REQUEST_TIMEOUT` at time `now`.
    ///
    /// Calls `on_abort(unique)` for each aborted request. Stops on first
    /// `Err` returned by `on_abort`.
    pub fn timeout_abort<F>(&mut self, now: u64, mut on_abort: F) -> Result<()>
    where
        F: FnMut(u64) -> Result<()>,
    {
        for e in &mut self.entries {
            if e.active && now.saturating_sub(e.submitted_at) >= REQUEST_TIMEOUT {
                on_abort(e.unique)?;
                *e = PendingRequest::empty();
            }
        }
        Ok(())
    }

    /// Return the number of active pending requests.
    pub fn active_count(&self) -> usize {
        self.entries.iter().filter(|e| e.active).count()
    }
}

// ---------------------------------------------------------------------------
// Byte-level serialisation helpers (no alloc)
// ---------------------------------------------------------------------------

fn header_as_bytes(hdr: &FuseOutHeader) -> &[u8] {
    // SAFETY: FuseOutHeader is repr(C) with no padding in any field group that
    // would cause UB when viewed as bytes; we only transmit it as-is over /dev/fuse.
    unsafe {
        core::slice::from_raw_parts(
            hdr as *const FuseOutHeader as *const u8,
            core::mem::size_of::<FuseOutHeader>(),
        )
    }
}

fn entry_out_as_bytes(e: &FuseEntryOut) -> &[u8] {
    // SAFETY: same as above; repr(C) struct used for wire protocol.
    unsafe {
        core::slice::from_raw_parts(
            e as *const FuseEntryOut as *const u8,
            core::mem::size_of::<FuseEntryOut>(),
        )
    }
}

fn attr_out_as_bytes(a: &FuseAttrOut) -> &[u8] {
    // SAFETY: repr(C) struct for wire protocol.
    unsafe {
        core::slice::from_raw_parts(
            a as *const FuseAttrOut as *const u8,
            core::mem::size_of::<FuseAttrOut>(),
        )
    }
}
