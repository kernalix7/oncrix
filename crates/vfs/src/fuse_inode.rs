// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! FUSE inode operations.
//!
//! Implements the kernel-side FUSE inode layer: attribute caching,
//! node-ID management, and request/response encoding for all inode-level
//! FUSE operations.
//!
//! # Design
//!
//! - [`FuseAttr`] — kernel copy of inode attributes
//! - [`FuseInode`] — per-inode FUSE state (nodeid, nlookup, attr cache)
//! - [`FuseRequest`] — kernel → userspace FUSE request
//! - [`FuseResponse`] — userspace → kernel FUSE response
//! - [`FuseInodeTable`] — nodeid-keyed inode table (up to 256 entries)
//! - [`FuseInodeOps`] — high-level inode operations dispatcher

use oncrix_lib::{Error, Result};

extern crate alloc;
use alloc::vec::Vec;

// ── Constants ───────────────────────────────────────────────────────────────

/// FUSE kernel protocol version (major).
pub const FUSE_KERNEL_VERSION: u32 = 7;

/// FUSE kernel protocol version (minor).
pub const FUSE_KERNEL_MINOR_VERSION: u32 = 38;

/// Root node ID (always 1 in FUSE).
pub const FUSE_ROOT_ID: u64 = 1;

/// Maximum inode table entries.
const MAX_INODES: usize = 256;

/// Default attribute timeout in seconds.
const DEFAULT_ATTR_TIMEOUT: u64 = 1;

/// Default entry timeout in seconds.
const DEFAULT_ENTRY_TIMEOUT: u64 = 1;

// ── FUSE opcode constants ────────────────────────────────────────────────────

pub const FUSE_LOOKUP: u32 = 1;
pub const FUSE_FORGET: u32 = 2;
pub const FUSE_GETATTR: u32 = 3;
pub const FUSE_SETATTR: u32 = 4;
pub const FUSE_READLINK: u32 = 5;
pub const FUSE_SYMLINK: u32 = 6;
pub const FUSE_MKNOD: u32 = 8;
pub const FUSE_MKDIR: u32 = 9;
pub const FUSE_UNLINK: u32 = 10;
pub const FUSE_RMDIR: u32 = 11;
pub const FUSE_RENAME: u32 = 12;
pub const FUSE_LINK: u32 = 13;
pub const FUSE_OPEN: u32 = 14;
pub const FUSE_READ: u32 = 15;
pub const FUSE_WRITE: u32 = 16;
pub const FUSE_STATFS: u32 = 17;
pub const FUSE_RELEASE: u32 = 18;
pub const FUSE_FSYNC: u32 = 20;
pub const FUSE_SETXATTR: u32 = 21;
pub const FUSE_GETXATTR: u32 = 22;
pub const FUSE_LISTXATTR: u32 = 23;
pub const FUSE_REMOVEXATTR: u32 = 24;
pub const FUSE_FLUSH: u32 = 25;
pub const FUSE_INIT: u32 = 26;
pub const FUSE_OPENDIR: u32 = 27;
pub const FUSE_READDIR: u32 = 28;
pub const FUSE_RELEASEDIR: u32 = 29;
pub const FUSE_FSYNCDIR: u32 = 30;
pub const FUSE_ACCESS: u32 = 34;
pub const FUSE_CREATE: u32 = 35;
pub const FUSE_INTERRUPT: u32 = 36;
pub const FUSE_BMAP: u32 = 37;
pub const FUSE_DESTROY: u32 = 38;

// ── SetAttr valid flags ─────────────────────────────────────────────────────

pub const FATTR_MODE: u32 = 1 << 0;
pub const FATTR_UID: u32 = 1 << 1;
pub const FATTR_GID: u32 = 1 << 2;
pub const FATTR_SIZE: u32 = 1 << 3;
pub const FATTR_ATIME: u32 = 1 << 4;
pub const FATTR_MTIME: u32 = 1 << 5;
pub const FATTR_FH: u32 = 1 << 6;
pub const FATTR_ATIME_NOW: u32 = 1 << 7;
pub const FATTR_MTIME_NOW: u32 = 1 << 8;
pub const FATTR_LOCKOWNER: u32 = 1 << 9;
pub const FATTR_CTIME: u32 = 1 << 10;

// ── FuseAttr ─────────────────────────────────────────────────────────────────

/// Kernel copy of FUSE inode attributes.
#[derive(Debug, Clone, Copy, Default)]
pub struct FuseAttr {
    /// Inode number (local to the FUSE filesystem).
    pub ino: u64,
    /// File size in bytes.
    pub size: u64,
    /// Number of 512-byte blocks allocated.
    pub blocks: u64,
    /// Access time (seconds since epoch).
    pub atime: u64,
    /// Modification time (seconds since epoch).
    pub mtime: u64,
    /// Status change time (seconds since epoch).
    pub ctime: u64,
    /// Access time nanosecond fraction.
    pub atimensec: u32,
    /// Modification time nanosecond fraction.
    pub mtimensec: u32,
    /// Status change time nanosecond fraction.
    pub ctimensec: u32,
    /// File mode and type bits.
    pub mode: u32,
    /// Hard link count.
    pub nlink: u32,
    /// User ID of owner.
    pub uid: u32,
    /// Group ID of owner.
    pub gid: u32,
    /// Device ID (for device special files).
    pub rdev: u32,
    /// Block size for filesystem I/O.
    pub blksize: u32,
}

impl FuseAttr {
    /// Create a default directory attribute.
    pub fn new_dir(ino: u64, uid: u32, gid: u32) -> Self {
        Self {
            ino,
            mode: 0o040755,
            nlink: 2,
            uid,
            gid,
            blksize: 4096,
            ..Default::default()
        }
    }

    /// Create a default regular-file attribute.
    pub fn new_file(ino: u64, size: u64, uid: u32, gid: u32) -> Self {
        Self {
            ino,
            size,
            mode: 0o0100644,
            nlink: 1,
            uid,
            gid,
            blksize: 4096,
            ..Default::default()
        }
    }
}

// ── FuseInode ────────────────────────────────────────────────────────────────

/// Per-inode FUSE kernel state.
#[derive(Debug, Clone)]
pub struct FuseInode {
    /// FUSE node ID assigned by the userspace daemon.
    pub nodeid: u64,
    /// Generation number (to detect recycled node IDs).
    pub generation: u64,
    /// Lookup reference count (incremented on LOOKUP, decremented on FORGET).
    pub nlookup: u64,
    /// Cached attributes.
    pub attr: FuseAttr,
    /// Attribute cache expiry (monotonic seconds).
    pub attr_timeout: u64,
    /// Entry cache expiry (monotonic seconds).
    pub entry_timeout: u64,
    /// True if the inode has been forgotten (nlookup reached 0).
    pub forgotten: bool,
}

impl FuseInode {
    /// Create a new FUSE inode.
    pub fn new(nodeid: u64, generation: u64, attr: FuseAttr) -> Self {
        Self {
            nodeid,
            generation,
            nlookup: 1,
            attr,
            attr_timeout: DEFAULT_ATTR_TIMEOUT,
            entry_timeout: DEFAULT_ENTRY_TIMEOUT,
            forgotten: false,
        }
    }

    /// Increment lookup count (LOOKUP hit).
    pub fn get(&mut self) {
        self.nlookup += 1;
    }

    /// Decrement lookup count by `nlookup`. Returns true if the inode should be evicted.
    pub fn forget(&mut self, nlookup: u64) -> bool {
        self.nlookup = self.nlookup.saturating_sub(nlookup);
        if self.nlookup == 0 {
            self.forgotten = true;
        }
        self.forgotten
    }

    /// Update cached attributes and refresh timeout.
    pub fn update_attr(&mut self, attr: FuseAttr, timeout: u64) {
        self.attr = attr;
        self.attr_timeout = timeout;
    }

    /// Returns true if the attribute cache has expired (relative to `now`).
    pub fn attr_expired(&self, now: u64) -> bool {
        now >= self.attr_timeout
    }
}

// ── FuseRequest ──────────────────────────────────────────────────────────────

/// Kernel-side FUSE request (sent to userspace).
#[derive(Debug, Clone)]
pub struct FuseRequest {
    /// Unique request ID.
    pub unique: u64,
    /// Operation code (FUSE_* constants).
    pub opcode: u32,
    /// Node ID this request targets.
    pub nodeid: u64,
    /// UID of the process making the request.
    pub uid: u32,
    /// GID of the process.
    pub gid: u32,
    /// PID of the process.
    pub pid: u32,
    /// Operation-specific arguments.
    pub args: Vec<u8>,
}

impl FuseRequest {
    /// Create a new FUSE request.
    pub fn new(unique: u64, opcode: u32, nodeid: u64, uid: u32, gid: u32, pid: u32) -> Self {
        Self {
            unique,
            opcode,
            nodeid,
            uid,
            gid,
            pid,
            args: Vec::new(),
        }
    }

    /// Append a u64 argument (little-endian, FUSE uses LE).
    pub fn push_u64(&mut self, v: u64) {
        self.args.extend_from_slice(&v.to_le_bytes());
    }

    /// Append a u32 argument.
    pub fn push_u32(&mut self, v: u32) {
        self.args.extend_from_slice(&v.to_le_bytes());
    }

    /// Append raw bytes.
    pub fn push_bytes(&mut self, b: &[u8]) {
        self.args.extend_from_slice(b);
        // Pad to 8-byte alignment
        let pad = (8 - (b.len() % 8)) % 8;
        for _ in 0..pad {
            self.args.push(0);
        }
    }

    /// Serialize the request header + args into a wire buffer.
    pub fn serialize(&self) -> Vec<u8> {
        // FUSE header: len(4) + opcode(4) + unique(8) + nodeid(8) + uid(4) + gid(4) + pid(4) + pad(4)
        let header_len = 40usize;
        let total = header_len + self.args.len();
        let mut buf = Vec::with_capacity(total);
        buf.extend_from_slice(&(total as u32).to_le_bytes());
        buf.extend_from_slice(&self.opcode.to_le_bytes());
        buf.extend_from_slice(&self.unique.to_le_bytes());
        buf.extend_from_slice(&self.nodeid.to_le_bytes());
        buf.extend_from_slice(&self.uid.to_le_bytes());
        buf.extend_from_slice(&self.gid.to_le_bytes());
        buf.extend_from_slice(&self.pid.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // padding
        buf.extend_from_slice(&self.args);
        buf
    }
}

// ── FuseResponse ─────────────────────────────────────────────────────────────

/// Parsed FUSE response from userspace.
#[derive(Debug, Clone)]
pub struct FuseResponse {
    /// Matching unique ID from the request.
    pub unique: u64,
    /// Error code (0 = success, negative = POSIX errno).
    pub error: i32,
    /// Response payload.
    pub data: Vec<u8>,
}

impl FuseResponse {
    /// Parse a FUSE response buffer.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 16 {
            return Err(Error::InvalidArgument);
        }
        let _len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let error = i32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let unique = u64::from_le_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]);
        let data = buf[16..].to_vec();
        Ok(Self {
            unique,
            error,
            data,
        })
    }

    /// Returns true if the response indicates success.
    pub fn is_ok(&self) -> bool {
        self.error == 0
    }

    /// Convert to a `Result`.
    pub fn into_result(self) -> Result<Vec<u8>> {
        if self.error == 0 {
            Ok(self.data)
        } else {
            Err(Error::IoError)
        }
    }

    /// Parse the embedded FuseAttr from an ENTRY or GETATTR response.
    pub fn parse_attr(&self) -> Result<(FuseAttr, u64, u64)> {
        // entry_valid(8) + entry_valid_nsec(4) + attr_valid(8) + attr_valid_nsec(4) + attr(88)
        if self.data.len() < 112 {
            return Err(Error::InvalidArgument);
        }
        let nodeid = u64::from_le_bytes(
            self.data[0..8]
                .try_into()
                .map_err(|_| Error::InvalidArgument)?,
        );
        let _nodeid_gen = u64::from_le_bytes(
            self.data[8..16]
                .try_into()
                .map_err(|_| Error::InvalidArgument)?,
        );
        let entry_valid = u64::from_le_bytes(
            self.data[16..24]
                .try_into()
                .map_err(|_| Error::InvalidArgument)?,
        );
        let _entry_valid_nsec = u32::from_le_bytes(
            self.data[24..28]
                .try_into()
                .map_err(|_| Error::InvalidArgument)?,
        );
        let attr_valid = u64::from_le_bytes(
            self.data[28..36]
                .try_into()
                .map_err(|_| Error::InvalidArgument)?,
        );
        let _attr_valid_nsec = u32::from_le_bytes(
            self.data[36..40]
                .try_into()
                .map_err(|_| Error::InvalidArgument)?,
        );

        // FuseAttr starts at offset 40
        let a = &self.data[40..];
        if a.len() < 72 {
            return Err(Error::InvalidArgument);
        }
        let attr = FuseAttr {
            ino: u64::from_le_bytes(a[0..8].try_into().map_err(|_| Error::InvalidArgument)?),
            size: u64::from_le_bytes(a[8..16].try_into().map_err(|_| Error::InvalidArgument)?),
            blocks: u64::from_le_bytes(a[16..24].try_into().map_err(|_| Error::InvalidArgument)?),
            atime: u64::from_le_bytes(a[24..32].try_into().map_err(|_| Error::InvalidArgument)?),
            mtime: u64::from_le_bytes(a[32..40].try_into().map_err(|_| Error::InvalidArgument)?),
            ctime: u64::from_le_bytes(a[40..48].try_into().map_err(|_| Error::InvalidArgument)?),
            atimensec: u32::from_le_bytes(
                a[48..52].try_into().map_err(|_| Error::InvalidArgument)?,
            ),
            mtimensec: u32::from_le_bytes(
                a[52..56].try_into().map_err(|_| Error::InvalidArgument)?,
            ),
            ctimensec: u32::from_le_bytes(
                a[56..60].try_into().map_err(|_| Error::InvalidArgument)?,
            ),
            mode: u32::from_le_bytes(a[60..64].try_into().map_err(|_| Error::InvalidArgument)?),
            nlink: u32::from_le_bytes(a[64..68].try_into().map_err(|_| Error::InvalidArgument)?),
            uid: u32::from_le_bytes(a[68..72].try_into().map_err(|_| Error::InvalidArgument)?),
            gid: if a.len() >= 76 {
                u32::from_le_bytes(a[72..76].try_into().map_err(|_| Error::InvalidArgument)?)
            } else {
                0
            },
            rdev: if a.len() >= 80 {
                u32::from_le_bytes(a[76..80].try_into().map_err(|_| Error::InvalidArgument)?)
            } else {
                0
            },
            blksize: if a.len() >= 84 {
                u32::from_le_bytes(a[80..84].try_into().map_err(|_| Error::InvalidArgument)?)
            } else {
                4096
            },
        };
        let _ = nodeid; // nodeid used to build FuseInode by caller
        Ok((attr, entry_valid, attr_valid))
    }
}

// ── FuseInodeTable ───────────────────────────────────────────────────────────

/// Node-ID keyed inode table.
pub struct FuseInodeTable {
    inodes: [Option<FuseInode>; MAX_INODES],
    count: usize,
    next_unique: u64,
}

impl FuseInodeTable {
    /// Create an empty inode table.
    pub fn new() -> Self {
        Self {
            inodes: core::array::from_fn(|_| None),
            count: 0,
            next_unique: 1,
        }
    }

    /// Insert a FUSE inode into the table.
    pub fn insert(&mut self, inode: FuseInode) -> Result<()> {
        if self.count >= MAX_INODES {
            return Err(Error::OutOfMemory);
        }
        for slot in &mut self.inodes {
            if slot.is_none() {
                *slot = Some(inode);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up an inode by node ID.
    pub fn get(&self, nodeid: u64) -> Option<&FuseInode> {
        for slot in &self.inodes {
            if let Some(inode) = slot {
                if inode.nodeid == nodeid {
                    return Some(inode);
                }
            }
        }
        None
    }

    /// Look up a mutable inode by node ID.
    pub fn get_mut(&mut self, nodeid: u64) -> Option<&mut FuseInode> {
        for slot in &mut self.inodes {
            if let Some(inode) = slot {
                if inode.nodeid == nodeid {
                    return Some(inode);
                }
            }
        }
        None
    }

    /// Remove an inode from the table.
    pub fn remove(&mut self, nodeid: u64) -> Option<FuseInode> {
        for slot in &mut self.inodes {
            if let Some(inode) = slot {
                if inode.nodeid == nodeid {
                    let removed = slot.take();
                    if removed.is_some() {
                        self.count -= 1;
                    }
                    return removed;
                }
            }
        }
        None
    }

    /// Allocate a new unique request ID.
    pub fn alloc_unique(&mut self) -> u64 {
        let u = self.next_unique;
        self.next_unique = self.next_unique.wrapping_add(1).max(1);
        u
    }

    /// Number of live inodes.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for FuseInodeTable {
    fn default() -> Self {
        Self::new()
    }
}

// ── FuseInodeOps ─────────────────────────────────────────────────────────────

/// High-level FUSE inode operations dispatcher.
pub struct FuseInodeOps {
    table: FuseInodeTable,
}

impl FuseInodeOps {
    /// Create a new dispatcher.
    pub fn new() -> Self {
        Self {
            table: FuseInodeTable::new(),
        }
    }

    /// Build a FUSE_LOOKUP request.
    pub fn build_lookup(&mut self, parent: u64, name: &[u8]) -> FuseRequest {
        let unique = self.table.alloc_unique();
        let mut req = FuseRequest::new(unique, FUSE_LOOKUP, parent, 0, 0, 0);
        req.push_bytes(name);
        req
    }

    /// Build a FUSE_FORGET request (does not get a reply).
    pub fn build_forget(&mut self, nodeid: u64, nlookup: u64) -> FuseRequest {
        let unique = self.table.alloc_unique();
        let mut req = FuseRequest::new(unique, FUSE_FORGET, nodeid, 0, 0, 0);
        req.push_u64(nlookup);
        req
    }

    /// Build a FUSE_GETATTR request.
    pub fn build_getattr(&mut self, nodeid: u64, fh: u64, flags: u32) -> FuseRequest {
        let unique = self.table.alloc_unique();
        let mut req = FuseRequest::new(unique, FUSE_GETATTR, nodeid, 0, 0, 0);
        req.push_u64(fh);
        req.push_u32(flags);
        req.push_u32(0); // padding
        req
    }

    /// Build a FUSE_SETATTR request.
    pub fn build_setattr(
        &mut self,
        nodeid: u64,
        attr: &FuseAttr,
        valid: u32,
        fh: u64,
    ) -> FuseRequest {
        let unique = self.table.alloc_unique();
        let mut req = FuseRequest::new(unique, FUSE_SETATTR, nodeid, 0, 0, 0);
        req.push_u64(fh);
        req.push_u32(valid);
        req.push_u32(0); // padding
        req.push_u64(attr.size);
        req.push_u64(attr.atime);
        req.push_u64(attr.mtime);
        req.push_u64(attr.ctime);
        req.push_u32(attr.atimensec);
        req.push_u32(attr.mtimensec);
        req.push_u32(attr.ctimensec);
        req.push_u32(attr.mode);
        req.push_u32(attr.uid);
        req.push_u32(attr.gid);
        req
    }

    /// Build a FUSE_MKNOD request.
    pub fn build_mknod(
        &mut self,
        parent: u64,
        name: &[u8],
        mode: u32,
        rdev: u32,
        umask: u32,
    ) -> FuseRequest {
        let unique = self.table.alloc_unique();
        let mut req = FuseRequest::new(unique, FUSE_MKNOD, parent, 0, 0, 0);
        req.push_u32(mode);
        req.push_u32(rdev);
        req.push_u32(umask);
        req.push_u32(0);
        req.push_bytes(name);
        req
    }

    /// Build a FUSE_MKDIR request.
    pub fn build_mkdir(&mut self, parent: u64, name: &[u8], mode: u32, umask: u32) -> FuseRequest {
        let unique = self.table.alloc_unique();
        let mut req = FuseRequest::new(unique, FUSE_MKDIR, parent, 0, 0, 0);
        req.push_u32(mode);
        req.push_u32(umask);
        req.push_bytes(name);
        req
    }

    /// Build a FUSE_UNLINK request.
    pub fn build_unlink(&mut self, parent: u64, name: &[u8]) -> FuseRequest {
        let unique = self.table.alloc_unique();
        let mut req = FuseRequest::new(unique, FUSE_UNLINK, parent, 0, 0, 0);
        req.push_bytes(name);
        req
    }

    /// Build a FUSE_RMDIR request.
    pub fn build_rmdir(&mut self, parent: u64, name: &[u8]) -> FuseRequest {
        let unique = self.table.alloc_unique();
        let mut req = FuseRequest::new(unique, FUSE_RMDIR, parent, 0, 0, 0);
        req.push_bytes(name);
        req
    }

    /// Build a FUSE_RENAME request.
    pub fn build_rename(
        &mut self,
        parent: u64,
        name: &[u8],
        newparent: u64,
        newname: &[u8],
        flags: u32,
    ) -> FuseRequest {
        let unique = self.table.alloc_unique();
        let mut req = FuseRequest::new(unique, FUSE_RENAME, parent, 0, 0, 0);
        req.push_u64(newparent);
        req.push_u32(flags);
        req.push_u32(0);
        req.push_bytes(name);
        req.push_bytes(newname);
        req
    }

    /// Build a FUSE_LINK request.
    pub fn build_link(&mut self, nodeid: u64, new_parent: u64, newname: &[u8]) -> FuseRequest {
        let unique = self.table.alloc_unique();
        let mut req = FuseRequest::new(unique, FUSE_LINK, nodeid, 0, 0, 0);
        req.push_u64(new_parent);
        req.push_bytes(newname);
        req
    }

    /// Build a FUSE_OPEN request.
    pub fn build_open(&mut self, nodeid: u64, flags: u32) -> FuseRequest {
        let unique = self.table.alloc_unique();
        let mut req = FuseRequest::new(unique, FUSE_OPEN, nodeid, 0, 0, 0);
        req.push_u32(flags);
        req.push_u32(0);
        req
    }

    /// Build a FUSE_READ request.
    pub fn build_read(&mut self, nodeid: u64, fh: u64, offset: u64, size: u32) -> FuseRequest {
        let unique = self.table.alloc_unique();
        let mut req = FuseRequest::new(unique, FUSE_READ, nodeid, 0, 0, 0);
        req.push_u64(fh);
        req.push_u64(offset);
        req.push_u32(size);
        req.push_u32(0);
        req
    }

    /// Build a FUSE_WRITE request.
    pub fn build_write(
        &mut self,
        nodeid: u64,
        fh: u64,
        offset: u64,
        data: &[u8],
        flags: u32,
    ) -> FuseRequest {
        let unique = self.table.alloc_unique();
        let mut req = FuseRequest::new(unique, FUSE_WRITE, nodeid, 0, 0, 0);
        req.push_u64(fh);
        req.push_u64(offset);
        req.push_u32(data.len() as u32);
        req.push_u32(flags);
        req.push_bytes(data);
        req
    }

    /// Process a LOOKUP reply: insert/update the inode table.
    pub fn handle_lookup_reply(
        &mut self,
        resp: &FuseResponse,
        nodeid: u64,
        cur_time: u64,
    ) -> Result<u64> {
        if !resp.is_ok() {
            return Err(Error::IoError);
        }
        let (attr, entry_valid, attr_valid) = resp.parse_attr()?;
        let timeout_abs = cur_time + attr_valid;

        if let Some(inode) = self.table.get_mut(nodeid) {
            inode.get();
            inode.update_attr(attr, timeout_abs);
        } else {
            let mut inode = FuseInode::new(nodeid, 0, attr);
            inode.attr_timeout = timeout_abs;
            inode.entry_timeout = cur_time + entry_valid;
            self.table.insert(inode)?;
        }
        Ok(nodeid)
    }

    /// Process a FORGET: decrement nlookup, possibly evict inode.
    pub fn handle_forget(&mut self, nodeid: u64, nlookup: u64) {
        if let Some(inode) = self.table.get_mut(nodeid) {
            let evict = inode.forget(nlookup);
            if evict {
                self.table.remove(nodeid);
            }
        }
    }

    /// Process a GETATTR reply: update cached attributes.
    pub fn handle_getattr_reply(
        &mut self,
        resp: &FuseResponse,
        nodeid: u64,
        cur_time: u64,
    ) -> Result<FuseAttr> {
        if !resp.is_ok() {
            return Err(Error::IoError);
        }
        let (attr, _entry_valid, attr_valid) = resp.parse_attr()?;
        if let Some(inode) = self.table.get_mut(nodeid) {
            inode.update_attr(attr, cur_time + attr_valid);
        }
        Ok(attr)
    }

    /// Returns a reference to the inode table.
    pub fn table(&self) -> &FuseInodeTable {
        &self.table
    }

    /// Returns a mutable reference to the inode table.
    pub fn table_mut(&mut self) -> &mut FuseInodeTable {
        &mut self.table
    }
}

impl Default for FuseInodeOps {
    fn default() -> Self {
        Self::new()
    }
}
