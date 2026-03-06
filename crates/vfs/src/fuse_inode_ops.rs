// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! FUSE filesystem inode operations.
//!
//! Implements the kernel side of the FUSE inode/directory operation
//! interface.  Each VFS inode operation is translated into a FUSE request
//! message, serialised, and forwarded to the userspace daemon via the FUSE
//! device.  The kernel then blocks until a matching FUSE response arrives.
//!
//! Covered operations (matching `fs/fuse/dir.c` and `fs/fuse/inode.c`):
//!
//! - lookup         — FUSE_LOOKUP
//! - getattr        — FUSE_GETATTR
//! - setattr        — FUSE_SETATTR
//! - create         — FUSE_CREATE
//! - mkdir          — FUSE_MKDIR
//! - unlink         — FUSE_UNLINK
//! - rmdir          — FUSE_RMDIR
//! - symlink        — FUSE_SYMLINK
//! - link           — FUSE_LINK
//! - rename         — FUSE_RENAME2
//! - attribute timeout / cache invalidation
//!
//! # Architecture
//!
//! ```text
//! VFS op  →  FuseInodeOps::{lookup,create,…}
//!               →  FuseRequest builder
//!                    →  encode into FuseReqBuf
//!                         →  FuseInodeConn::submit()
//!                              ← FuseResponse received from daemon
//!                                   → decode result fields
//!                                        → update attr cache
//! ```
//!
//! # Attribute Caching
//!
//! Each node entry caches the userspace-reported attributes for
//! `attr_timeout_ms` milliseconds.  [`AttrCache`] is a fixed 256-slot
//! table indexed by FUSE node ID.
//!
//! # Structures
//!
//! - [`FuseOpcode`]       — inode-related FUSE opcodes
//! - [`FuseAttr`]         — `repr(C)` attribute block returned by daemon
//! - [`FuseEntryOut`]     — lookup / create reply body
//! - [`FuseAttrOut`]      — getattr reply body
//! - [`FuseSetAttrIn`]    — setattr request body
//! - [`FuseCreateIn`]     — create request body
//! - [`FuseMkdirIn`]      — mkdir request body
//! - [`FuseRenameIn`]     — rename request body
//! - [`FuseLinkIn`]       — link request body
//! - [`AttrCacheEntry`]   — cached attributes with TTL
//! - [`AttrCache`]        — 256-slot attribute cache
//! - [`FuseReqBuf`]       — encode buffer for FUSE requests
//! - [`FuseInodeConn`]    — pending request queue + submission
//! - [`FuseInodeOps`]     — top-level inode operation handler

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────────────

/// Maximum FUSE request/response payload size (4 KiB + header).
const MAX_FUSE_BUF: usize = 4096 + 64;

/// Maximum filename length in a FUSE request.
const MAX_NAME_LEN: usize = 255;

/// Maximum symlink target length.
const MAX_SYMLINK_LEN: usize = 4096;

/// Maximum number of pending FUSE requests per connection.
const MAX_PENDING: usize = 64;

/// Maximum attribute cache entries.
const MAX_ATTR_CACHE: usize = 256;

/// Default attribute timeout in milliseconds (1 s).
const DEFAULT_ATTR_TIMEOUT_MS: u64 = 1_000;

/// Monotonic tick counter (placeholder — kernel integrates real timer).
static TICK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

fn current_tick() -> u64 {
    TICK.load(core::sync::atomic::Ordering::Relaxed)
}

// ── FuseOpcode ───────────────────────────────────────────────────────────────

/// Inode-related FUSE operation codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FuseOpcode {
    /// Look up a directory entry by name.
    Lookup = 1,
    /// Forget a node ID (decrement ref count).
    Forget = 2,
    /// Get file attributes.
    Getattr = 3,
    /// Set file attributes.
    Setattr = 4,
    /// Read symbolic link target.
    Readlink = 5,
    /// Create a symbolic link.
    Symlink = 6,
    /// Create a file.
    Mknod = 8,
    /// Create a directory.
    Mkdir = 9,
    /// Remove a file.
    Unlink = 10,
    /// Remove a directory.
    Rmdir = 11,
    /// Rename a directory entry.
    Rename = 12,
    /// Create a hard link.
    Link = 13,
    /// Create a file and open it.
    Create = 35,
    /// Rename with flags (RENAME2).
    Rename2 = 45,
}

// ── FuseAttr ─────────────────────────────────────────────────────────────────

/// Inode attribute block as defined by the FUSE wire protocol.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FuseAttr {
    /// Inode number.
    pub ino: u64,
    /// File size in bytes.
    pub size: u64,
    /// Allocated blocks (512-byte units).
    pub blocks: u64,
    /// Access time (seconds).
    pub atime: u64,
    /// Modification time (seconds).
    pub mtime: u64,
    /// Status change time (seconds).
    pub ctime: u64,
    /// Access time nanoseconds.
    pub atimensec: u32,
    /// Modification time nanoseconds.
    pub mtimensec: u32,
    /// Status change time nanoseconds.
    pub ctimensec: u32,
    /// File mode (permissions + type).
    pub mode: u32,
    /// Number of hard links.
    pub nlink: u32,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// Device number (for special files).
    pub rdev: u32,
    /// Block size.
    pub blksize: u32,
    /// Padding.
    pub padding: u32,
}

// ── FuseEntryOut ─────────────────────────────────────────────────────────────

/// Reply body for LOOKUP, CREATE, MKDIR, SYMLINK, MKNOD, LINK.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FuseEntryOut {
    /// FUSE node ID assigned to the new entry.
    pub nodeid: u64,
    /// Generation number (incremented on inode reuse).
    pub generation: u64,
    /// Attribute cache timeout (seconds).
    pub entry_valid: u64,
    /// Entry timeout nanoseconds fraction.
    pub attr_valid: u64,
    /// Entry valid seconds.
    pub entry_valid_nsec: u32,
    /// Attribute valid nanoseconds.
    pub attr_valid_nsec: u32,
    /// Inode attributes.
    pub attr: FuseAttr,
}

// ── FuseAttrOut ──────────────────────────────────────────────────────────────

/// Reply body for GETATTR.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FuseAttrOut {
    /// Attribute cache TTL (seconds).
    pub attr_valid: u64,
    /// Attribute cache TTL (nanoseconds fraction).
    pub attr_valid_nsec: u32,
    /// Padding.
    pub dummy: u32,
    /// Inode attributes.
    pub attr: FuseAttr,
}

// ── FuseSetAttrIn ────────────────────────────────────────────────────────────

/// Request body for SETATTR.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FuseSetAttrIn {
    /// Bitmask of fields to set.
    pub valid: u32,
    /// File handle (if FATTR_FH is set).
    pub fh: u64,
    /// New size.
    pub size: u64,
    /// Lock owner.
    pub lock_owner: u64,
    /// New atime seconds.
    pub atime: u64,
    /// New mtime seconds.
    pub mtime: u64,
    /// New ctime seconds.
    pub ctime: u64,
    /// New atime nanoseconds.
    pub atimensec: u32,
    /// New mtime nanoseconds.
    pub mtimensec: u32,
    /// New ctimensec.
    pub ctimensec: u32,
    /// New mode.
    pub mode: u32,
    /// Unused.
    pub unused4: u32,
    /// New uid.
    pub uid: u32,
    /// New gid.
    pub gid: u32,
    /// Unused.
    pub unused5: u32,
}

// ── FuseCreateIn ─────────────────────────────────────────────────────────────

/// Request body for CREATE (preceding the filename).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FuseCreateIn {
    /// Open flags (O_CREAT | O_TRUNC etc.).
    pub flags: u32,
    /// Creation mode.
    pub mode: u32,
    /// umask.
    pub umask: u32,
    /// Padding.
    pub padding: u32,
}

// ── FuseMkdirIn ──────────────────────────────────────────────────────────────

/// Request body for MKDIR (preceding the directory name).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FuseMkdirIn {
    /// Directory mode.
    pub mode: u32,
    /// umask.
    pub umask: u32,
}

// ── FuseRenameIn ─────────────────────────────────────────────────────────────

/// Request body for RENAME / RENAME2.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FuseRenameIn {
    /// Node ID of the destination parent directory.
    pub newdir: u64,
    /// Rename flags (RENAME_NOREPLACE, RENAME_EXCHANGE, …).
    pub flags: u32,
    /// Padding.
    pub padding: u32,
}

// ── FuseLinkIn ───────────────────────────────────────────────────────────────

/// Request body for LINK.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FuseLinkIn {
    /// Node ID of the source inode.
    pub oldnodeid: u64,
}

// ── AttrCacheEntry ───────────────────────────────────────────────────────────

/// One slot in the attribute cache.
#[derive(Debug, Clone, Copy)]
pub struct AttrCacheEntry {
    /// FUSE node ID.
    pub nodeid: u64,
    /// Cached attributes.
    pub attr: FuseAttr,
    /// Tick at which the entry expires.
    pub expire_tick: u64,
    /// Whether this slot is populated.
    pub in_use: bool,
}

impl AttrCacheEntry {
    /// Create an empty slot.
    pub const fn empty() -> Self {
        Self {
            nodeid: 0,
            attr: FuseAttr {
                ino: 0,
                size: 0,
                blocks: 0,
                atime: 0,
                mtime: 0,
                ctime: 0,
                atimensec: 0,
                mtimensec: 0,
                ctimensec: 0,
                mode: 0,
                nlink: 0,
                uid: 0,
                gid: 0,
                rdev: 0,
                blksize: 0,
                padding: 0,
            },
            expire_tick: 0,
            in_use: false,
        }
    }
}

// ── AttrCache ────────────────────────────────────────────────────────────────

/// Fixed-size attribute cache keyed by FUSE node ID.
pub struct AttrCache {
    /// Cache entries.
    entries: [AttrCacheEntry; MAX_ATTR_CACHE],
    /// Default TTL in milliseconds.
    default_ttl_ms: u64,
}

impl AttrCache {
    /// Create an empty attribute cache with `ttl_ms` millisecond lifetime.
    pub fn new(ttl_ms: u64) -> Self {
        Self {
            entries: [const { AttrCacheEntry::empty() }; MAX_ATTR_CACHE],
            default_ttl_ms: ttl_ms,
        }
    }

    /// Insert or update the cached attributes for `nodeid`.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the cache is full and no expired entries can be
    ///   evicted.
    pub fn insert(&mut self, nodeid: u64, attr: FuseAttr) -> Result<()> {
        let now = current_tick();
        // Look for existing entry or empty slot or expired slot.
        let mut target = None;
        for (i, e) in self.entries.iter().enumerate() {
            if e.in_use && e.nodeid == nodeid {
                target = Some(i);
                break;
            }
            if !e.in_use || e.expire_tick <= now {
                target = Some(i);
                // Keep searching for an exact match.
            }
        }
        let idx = target.ok_or(Error::OutOfMemory)?;
        self.entries[idx] = AttrCacheEntry {
            nodeid,
            attr,
            expire_tick: now.saturating_add(self.default_ttl_ms),
            in_use: true,
        };
        Ok(())
    }

    /// Look up cached attributes for `nodeid`.
    ///
    /// Returns `None` if the entry is missing or expired.
    pub fn lookup(&self, nodeid: u64) -> Option<&FuseAttr> {
        let now = current_tick();
        self.entries.iter().find_map(|e| {
            if e.in_use && e.nodeid == nodeid && e.expire_tick > now {
                Some(&e.attr)
            } else {
                None
            }
        })
    }

    /// Invalidate the cached entry for `nodeid`.
    pub fn invalidate(&mut self, nodeid: u64) {
        for e in self.entries.iter_mut() {
            if e.in_use && e.nodeid == nodeid {
                e.in_use = false;
            }
        }
    }
}

// ── FuseReqBuf ───────────────────────────────────────────────────────────────

/// Encode buffer for FUSE request messages.
pub struct FuseReqBuf {
    data: [u8; MAX_FUSE_BUF],
    pos: usize,
    len: usize,
}

impl FuseReqBuf {
    /// Create an empty buffer.
    pub fn new() -> Self {
        Self {
            data: [0u8; MAX_FUSE_BUF],
            pos: 0,
            len: 0,
        }
    }

    /// Append raw bytes.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the buffer is full.
    pub fn put_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        if self.pos + bytes.len() > MAX_FUSE_BUF {
            return Err(Error::OutOfMemory);
        }
        self.data[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
        self.len = self.pos;
        Ok(())
    }

    /// Append a u32 in little-endian (FUSE wire format).
    pub fn put_u32(&mut self, v: u32) -> Result<()> {
        self.put_bytes(&v.to_le_bytes())
    }

    /// Append a u64 in little-endian.
    pub fn put_u64(&mut self, v: u64) -> Result<()> {
        self.put_bytes(&v.to_le_bytes())
    }

    /// Append a NUL-terminated filename.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if the name is longer than `MAX_NAME_LEN`.
    /// - `OutOfMemory` if the buffer overflows.
    pub fn put_name(&mut self, name: &[u8]) -> Result<()> {
        if name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        self.put_bytes(name)?;
        self.put_bytes(&[0u8]) // NUL terminator
    }

    /// Return the encoded bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Reset the buffer.
    pub fn reset(&mut self) {
        self.pos = 0;
        self.len = 0;
    }
}

impl Default for FuseReqBuf {
    fn default() -> Self {
        Self::new()
    }
}

// ── FuseInodeConn ────────────────────────────────────────────────────────────

/// Tracks a pending FUSE request submitted to the daemon.
#[derive(Debug, Clone, Copy)]
struct PendingReq {
    /// Unique ID of this request.
    unique: u64,
    /// Opcode.
    opcode: FuseOpcode,
    /// Whether this slot is occupied.
    in_use: bool,
}

impl PendingReq {
    const fn empty() -> Self {
        Self {
            unique: 0,
            opcode: FuseOpcode::Lookup,
            in_use: false,
        }
    }
}

/// Submission queue for FUSE requests, simulating the kernel-daemon
/// round-trip.
pub struct FuseInodeConn {
    /// Pending request slots.
    pending: [PendingReq; MAX_PENDING],
    /// Number of in-flight requests.
    count: usize,
    /// Monotonically increasing unique request ID.
    next_unique: u64,
}

impl FuseInodeConn {
    /// Create a new connection queue.
    pub fn new() -> Self {
        Self {
            pending: [const { PendingReq::empty() }; MAX_PENDING],
            count: 0,
            next_unique: 1,
        }
    }

    /// Submit a request, returning its unique ID.
    ///
    /// # Errors
    ///
    /// - `Busy` if the queue is full.
    pub fn submit(&mut self, opcode: FuseOpcode) -> Result<u64> {
        if self.count >= MAX_PENDING {
            return Err(Error::Busy);
        }
        let unique = self.next_unique;
        self.next_unique = self.next_unique.wrapping_add(1);
        let slot = self
            .pending
            .iter()
            .position(|p| !p.in_use)
            .ok_or(Error::Busy)?;
        self.pending[slot] = PendingReq {
            unique,
            opcode,
            in_use: true,
        };
        self.count += 1;
        Ok(unique)
    }

    /// Complete (dequeue) the pending request with the given unique ID.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no pending request has `unique`.
    pub fn complete(&mut self, unique: u64) -> Result<()> {
        let pos = self
            .pending
            .iter()
            .position(|p| p.in_use && p.unique == unique)
            .ok_or(Error::NotFound)?;
        self.pending[pos] = PendingReq::empty();
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Number of in-flight requests.
    pub fn pending_count(&self) -> usize {
        self.count
    }
}

impl Default for FuseInodeConn {
    fn default() -> Self {
        Self::new()
    }
}

// ── FuseInodeOps ─────────────────────────────────────────────────────────────

/// Top-level FUSE inode operation handler.
///
/// Translates VFS inode calls into FUSE request/response exchanges with the
/// userspace daemon, caching attributes along the way.
pub struct FuseInodeOps {
    /// Attribute cache.
    attr_cache: AttrCache,
    /// Pending request queue.
    conn: FuseInodeConn,
    /// Encode buffer.
    req_buf: FuseReqBuf,
    /// FUSE node ID counter (assigned by the kernel side on lookup results).
    next_nodeid: u64,
    /// Total lookup requests.
    lookup_count: u64,
    /// Total setattr requests.
    setattr_count: u64,
}

impl FuseInodeOps {
    /// Create a new inode ops handler.
    pub fn new() -> Self {
        Self {
            attr_cache: AttrCache::new(DEFAULT_ATTR_TIMEOUT_MS),
            conn: FuseInodeConn::new(),
            req_buf: FuseReqBuf::new(),
            next_nodeid: 2, // 1 is the root node.
            lookup_count: 0,
            setattr_count: 0,
        }
    }

    /// Perform a FUSE_LOOKUP for `name` in directory node `parent`.
    ///
    /// Encodes the request and submits it to the connection queue.
    /// On a real system the daemon fills in the reply; here we return the
    /// unique request ID so the caller can later call `complete_lookup`.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if the name is too long.
    /// - `Busy` if the request queue is full.
    /// - `OutOfMemory` if the encode buffer overflows.
    pub fn lookup(&mut self, parent: u64, name: &[u8]) -> Result<u64> {
        self.req_buf.reset();
        // Node ID of the parent directory.
        self.req_buf.put_u64(parent)?;
        self.req_buf.put_name(name)?;
        let unique = self.conn.submit(FuseOpcode::Lookup)?;
        self.lookup_count += 1;
        Ok(unique)
    }

    /// Finalise a FUSE_LOOKUP reply, recording the entry in the attr cache.
    ///
    /// # Errors
    ///
    /// - `NotFound` if `unique` does not match a pending lookup.
    /// - `OutOfMemory` if the attr cache is full.
    pub fn complete_lookup(&mut self, unique: u64, entry: FuseEntryOut) -> Result<u64> {
        self.conn.complete(unique)?;
        self.attr_cache.insert(entry.nodeid, entry.attr)?;
        Ok(entry.nodeid)
    }

    /// Perform a FUSE_GETATTR for `nodeid`.
    ///
    /// Returns cached attributes if still valid, otherwise submits a request.
    ///
    /// # Errors
    ///
    /// - `Busy` if the queue is full and a fresh fetch is needed.
    pub fn getattr(&mut self, nodeid: u64) -> Result<Option<FuseAttr>> {
        if let Some(attr) = self.attr_cache.lookup(nodeid) {
            return Ok(Some(*attr));
        }
        // Stale or missing — submit a GETATTR request.
        self.conn.submit(FuseOpcode::Getattr)?;
        Ok(None)
    }

    /// Finalise a FUSE_GETATTR reply.
    ///
    /// # Errors
    ///
    /// - `NotFound` if `unique` does not match a pending request.
    /// - `OutOfMemory` if the attr cache is full.
    pub fn complete_getattr(&mut self, unique: u64, nodeid: u64, attr: FuseAttr) -> Result<()> {
        self.conn.complete(unique)?;
        self.attr_cache.insert(nodeid, attr)
    }

    /// Encode and submit a FUSE_SETATTR request.
    ///
    /// # Errors
    ///
    /// - `Busy` if the queue is full.
    /// - `OutOfMemory` if the encode buffer overflows.
    pub fn setattr(&mut self, nodeid: u64, req: &FuseSetAttrIn) -> Result<u64> {
        self.req_buf.reset();
        self.req_buf.put_u64(nodeid)?;
        // Encode FuseSetAttrIn fields.
        self.req_buf.put_u32(req.valid)?;
        self.req_buf.put_u64(req.fh)?;
        self.req_buf.put_u64(req.size)?;
        self.req_buf.put_u32(req.mode)?;
        self.req_buf.put_u32(req.uid)?;
        self.req_buf.put_u32(req.gid)?;
        let unique = self.conn.submit(FuseOpcode::Setattr)?;
        // Invalidate cached attrs immediately.
        self.attr_cache.invalidate(nodeid);
        self.setattr_count += 1;
        Ok(unique)
    }

    /// Encode and submit a FUSE_CREATE request.
    ///
    /// Returns the unique request ID.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if the name is too long.
    /// - `Busy` if the queue is full.
    /// - `OutOfMemory` if the encode buffer overflows.
    pub fn create(&mut self, parent: u64, name: &[u8], req: &FuseCreateIn) -> Result<u64> {
        self.req_buf.reset();
        self.req_buf.put_u64(parent)?;
        self.req_buf.put_u32(req.flags)?;
        self.req_buf.put_u32(req.mode)?;
        self.req_buf.put_u32(req.umask)?;
        self.req_buf.put_name(name)?;
        self.conn.submit(FuseOpcode::Create)
    }

    /// Encode and submit a FUSE_MKDIR request.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if the name is too long.
    /// - `Busy` if the queue is full.
    pub fn mkdir(&mut self, parent: u64, name: &[u8], req: &FuseMkdirIn) -> Result<u64> {
        self.req_buf.reset();
        self.req_buf.put_u64(parent)?;
        self.req_buf.put_u32(req.mode)?;
        self.req_buf.put_u32(req.umask)?;
        self.req_buf.put_name(name)?;
        self.conn.submit(FuseOpcode::Mkdir)
    }

    /// Encode and submit a FUSE_UNLINK request.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if the name is too long.
    /// - `Busy` if the queue is full.
    pub fn unlink(&mut self, parent: u64, name: &[u8]) -> Result<u64> {
        self.req_buf.reset();
        self.req_buf.put_u64(parent)?;
        self.req_buf.put_name(name)?;
        self.conn.submit(FuseOpcode::Unlink)
    }

    /// Encode and submit a FUSE_RMDIR request.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if the name is too long.
    /// - `Busy` if the queue is full.
    pub fn rmdir(&mut self, parent: u64, name: &[u8]) -> Result<u64> {
        self.req_buf.reset();
        self.req_buf.put_u64(parent)?;
        self.req_buf.put_name(name)?;
        self.conn.submit(FuseOpcode::Rmdir)
    }

    /// Encode and submit a FUSE_SYMLINK request.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if either name or link target is too long.
    /// - `Busy` if the queue is full.
    pub fn symlink(&mut self, parent: u64, name: &[u8], target: &[u8]) -> Result<u64> {
        if target.len() > MAX_SYMLINK_LEN {
            return Err(Error::InvalidArgument);
        }
        self.req_buf.reset();
        self.req_buf.put_u64(parent)?;
        self.req_buf.put_name(name)?;
        self.req_buf.put_name(target)?;
        self.conn.submit(FuseOpcode::Symlink)
    }

    /// Encode and submit a FUSE_LINK request.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `newname` is too long.
    /// - `Busy` if the queue is full.
    pub fn link(&mut self, oldnodeid: u64, newparent: u64, newname: &[u8]) -> Result<u64> {
        self.req_buf.reset();
        let req = FuseLinkIn { oldnodeid };
        self.req_buf.put_u64(req.oldnodeid)?;
        self.req_buf.put_u64(newparent)?;
        self.req_buf.put_name(newname)?;
        self.conn.submit(FuseOpcode::Link)
    }

    /// Encode and submit a FUSE_RENAME2 request.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if either name is too long.
    /// - `Busy` if the queue is full.
    pub fn rename(
        &mut self,
        oldparent: u64,
        oldname: &[u8],
        newparent: u64,
        newname: &[u8],
        flags: u32,
    ) -> Result<u64> {
        self.req_buf.reset();
        self.req_buf.put_u64(oldparent)?;
        let rin = FuseRenameIn {
            newdir: newparent,
            flags,
            padding: 0,
        };
        self.req_buf.put_u64(rin.newdir)?;
        self.req_buf.put_u32(rin.flags)?;
        self.req_buf.put_u32(0)?; // padding
        self.req_buf.put_name(oldname)?;
        self.req_buf.put_name(newname)?;
        self.conn.submit(FuseOpcode::Rename2)
    }

    /// Invalidate all cached attributes for `nodeid`.
    pub fn invalidate_attr(&mut self, nodeid: u64) {
        self.attr_cache.invalidate(nodeid);
    }

    /// Number of pending FUSE requests.
    pub fn pending_count(&self) -> usize {
        self.conn.pending_count()
    }

    /// Total FUSE_LOOKUP requests issued.
    pub fn lookup_count(&self) -> u64 {
        self.lookup_count
    }

    /// Total FUSE_SETATTR requests issued.
    pub fn setattr_count(&self) -> u64 {
        self.setattr_count
    }

    /// Allocate and return the next FUSE node ID.
    pub fn alloc_nodeid(&mut self) -> u64 {
        let id = self.next_nodeid;
        self.next_nodeid = self.next_nodeid.wrapping_add(1);
        id
    }
}

impl Default for FuseInodeOps {
    fn default() -> Self {
        Self::new()
    }
}
