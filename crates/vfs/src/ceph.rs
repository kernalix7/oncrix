// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Ceph distributed filesystem client.
//!
//! Implements a minimal Ceph FS client that communicates with the Metadata
//! Server (MDS) for namespace operations and with Object Storage Daemons
//! (OSDs) for data I/O. The client maintains an inode cache and capability
//! set per inode.
//!
//! # Architecture
//!
//! ```text
//! CephFs
//!   ├── CephMdsSession  — MDS connection state + session handshake
//!   ├── InodeCache      — LRU cache of 256 CephInode entries
//!   └── OsdMap          — (stub) OSD cluster topology
//!         └── OsdRequest → OsdReply  — per-object read/write ops
//! ```
//!
//! # Structures
//!
//! - [`MdsState`] — MDS session lifecycle state machine
//! - [`CephMdsSession`] — MDS session (session_id, state, addr)
//! - [`CapFlags`] — per-inode capability bitflags
//! - [`CephCap`] — single capability grant from MDS
//! - [`CapSet`] — per-inode capability tracker (max 4 caps)
//! - [`CephInode`] — cached inode with capabilities
//! - [`InodeCache`] — 256-entry LRU inode cache
//! - [`OsdOpType`] — OSD operation selector
//! - [`OsdRequest`] — OSD operation request
//! - [`OsdReply`] — OSD operation response
//! - [`OsdMap`] — OSD cluster map (stub)
//! - [`CephFs`] — top-level Ceph FS client handle

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────

/// Maximum number of inodes in the LRU inode cache.
const MAX_INODE_CACHE: usize = 256;

/// Maximum number of concurrent capabilities per inode.
const MAX_CAPS_PER_INODE: usize = 4;

/// Maximum length of a filename in bytes.
const MAX_NAME_LEN: usize = 256;

/// Maximum number of directory entries returned by [`CephFs::readdir`].
const MAX_DIR_ENTRIES: usize = 128;

/// Maximum OSD data payload size in bytes.
const MAX_OSD_DATA: usize = 65536;

// ── MdsState ────────────────────────────────────────────────────

/// Lifecycle state of a Ceph MDS session.
///
/// Sessions transition linearly: `Opening` → `Open` → `Closing` → `Closed`.
/// A reconnect resets the session back through `Opening`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdsState {
    /// Session creation in progress (waiting for MDS reply).
    Opening,
    /// Session is established and fully operational.
    Open,
    /// Session close is in progress (draining caps).
    Closing,
    /// Session has been closed or has not yet been initiated.
    Closed,
}

// ── CephMdsSession ───────────────────────────────────────────────

/// An MDS session representing the client's connection to one MDS.
///
/// Each MDS session has a unique numeric `session_id` assigned by the
/// MDS. The `mds_addr` encodes the MDS network address as a u64 for
/// portability in a no_std environment.
#[derive(Debug, Clone, Copy)]
pub struct CephMdsSession {
    /// Unique session identifier assigned by the MDS.
    pub session_id: u64,
    /// Current lifecycle state of the session.
    pub state: MdsState,
    /// MDS network address (encoded as a u64, e.g., IPv4 addr + port).
    pub mds_addr: u64,
    /// Client epoch for session reconnection.
    pub epoch: u32,
    /// Sequence number for request correlation.
    pub seq: u64,
}

impl CephMdsSession {
    /// Create a new session in the `Closed` state.
    pub fn new() -> Self {
        Self {
            session_id: 0,
            state: MdsState::Closed,
            mds_addr: 0,
            epoch: 0,
            seq: 0,
        }
    }

    /// Initiate a session to the given MDS address.
    ///
    /// Transitions from `Closed` to `Opening`. Returns `Busy` if already
    /// open or opening.
    pub fn open(&mut self, mds_addr: u64) -> Result<()> {
        if self.state != MdsState::Closed {
            return Err(Error::Busy);
        }
        self.mds_addr = mds_addr;
        self.state = MdsState::Opening;
        self.seq = 0;
        Ok(())
    }

    /// Acknowledge the MDS session response and mark the session open.
    ///
    /// Returns `InvalidArgument` if called from a state other than `Opening`.
    pub fn confirm_open(&mut self, session_id: u64, epoch: u32) -> Result<()> {
        if self.state != MdsState::Opening {
            return Err(Error::InvalidArgument);
        }
        self.session_id = session_id;
        self.epoch = epoch;
        self.state = MdsState::Open;
        Ok(())
    }

    /// Begin closing the session.
    ///
    /// Returns `InvalidArgument` if the session is not open.
    pub fn close(&mut self) -> Result<()> {
        if self.state != MdsState::Open {
            return Err(Error::InvalidArgument);
        }
        self.state = MdsState::Closing;
        Ok(())
    }

    /// Finalize the close and return the session to `Closed`.
    pub fn finalize_close(&mut self) {
        self.state = MdsState::Closed;
        self.session_id = 0;
    }

    /// Return the next request sequence number.
    pub fn next_seq(&mut self) -> u64 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        s
    }

    /// Whether the session is in the `Open` state.
    pub fn is_open(&self) -> bool {
        self.state == MdsState::Open
    }
}

impl Default for CephMdsSession {
    fn default() -> Self {
        Self::new()
    }
}

// ── CapFlags ────────────────────────────────────────────────────

/// Bitflags representing capability grants on a Ceph inode.
///
/// Each bit corresponds to a permission the MDS has granted to this
/// client for a specific inode. Capabilities must be explicitly requested
/// and are revoked by the MDS when the inode is accessed by other clients.
pub struct CapFlags(pub u32);

impl CapFlags {
    /// No capabilities.
    pub const NONE: u32 = 0x0000_0000;
    /// Permission to read file data (Ceph CAP_FILE_RD).
    pub const READ: u32 = 0x0000_0002;
    /// Permission to write file data (Ceph CAP_FILE_WR).
    pub const WRITE: u32 = 0x0000_0004;
    /// Permission to cache file data in the page cache (Ceph CAP_FILE_CACHE).
    pub const CACHE: u32 = 0x0000_0008;
    /// Lazy I/O permission — allows buffered writes without immediate flush (Ceph CAP_FILE_LAZYIO).
    pub const LAZY: u32 = 0x0000_0010;
    /// Permission to read file metadata (Ceph CAP_FILE_SHARED).
    pub const SHARED: u32 = 0x0000_0020;
    /// Permission to exclusively modify metadata (Ceph CAP_FILE_EXCL).
    pub const EXCL: u32 = 0x0000_0040;

    /// Create a new CapFlags from a raw bitfield.
    pub fn new(bits: u32) -> Self {
        Self(bits)
    }

    /// Check whether the given flag bits are all set.
    pub fn has(&self, flag: u32) -> bool {
        (self.0 & flag) == flag
    }

    /// Set additional flag bits.
    pub fn grant(&mut self, flag: u32) {
        self.0 |= flag;
    }

    /// Clear the given flag bits.
    pub fn revoke(&mut self, flag: u32) {
        self.0 &= !flag;
    }

    /// Return the raw bitfield.
    pub fn bits(&self) -> u32 {
        self.0
    }
}

impl core::fmt::Debug for CapFlags {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("CapFlags")
            .field(&format_args!("{:#010x}", self.0))
            .finish()
    }
}

// ── CephCap ──────────────────────────────────────────────────────

/// A single capability grant from the MDS for one inode.
///
/// Capabilities authorize specific operations (read, write, cache, etc.)
/// on a per-inode basis. The MDS may issue, update, or revoke caps at any
/// time via session messages.
#[derive(Debug, Clone, Copy)]
pub struct CephCap {
    /// Inode number this capability applies to.
    pub ino: u64,
    /// MDS-assigned capability identifier.
    pub cap_id: u64,
    /// Bitmask of issued permissions.
    pub issued: u32,
    /// Bitmask of implemented (locally used) permissions.
    pub implemented: u32,
    /// Cap sequence number from the MDS.
    pub seq: u32,
    /// Whether this cap slot is occupied.
    pub valid: bool,
}

impl CephCap {
    /// Create an empty (invalid) capability slot.
    pub const fn empty() -> Self {
        Self {
            ino: 0,
            cap_id: 0,
            issued: CapFlags::NONE,
            implemented: CapFlags::NONE,
            seq: 0,
            valid: false,
        }
    }

    /// Create a new capability with the given parameters.
    pub fn new(ino: u64, cap_id: u64, issued: u32) -> Self {
        Self {
            ino,
            cap_id,
            issued,
            implemented: 0,
            seq: 0,
            valid: true,
        }
    }

    /// Whether the given permission is issued.
    pub fn has(&self, flag: u32) -> bool {
        self.valid && (self.issued & flag) == flag
    }
}

// ── CapSet ────────────────────────────────────────────────────────

/// Per-inode capability set tracking up to [`MAX_CAPS_PER_INODE`] concurrent caps.
///
/// Each inode may hold capabilities from multiple MDS instances (in multi-MDS
/// deployments). This set tracks all outstanding caps for a single inode.
#[derive(Debug, Clone, Copy)]
pub struct CapSet {
    /// Capability slots.
    caps: [CephCap; MAX_CAPS_PER_INODE],
    /// Number of valid (issued) caps.
    count: usize,
}

impl CapSet {
    /// Create an empty capability set.
    pub const fn new() -> Self {
        Self {
            caps: [CephCap::empty(); MAX_CAPS_PER_INODE],
            count: 0,
        }
    }

    /// Add or update a capability in the set.
    ///
    /// If a cap with the same `cap_id` exists, its `issued` bits are updated.
    /// Returns `OutOfMemory` if the set is full.
    pub fn insert(&mut self, cap: CephCap) -> Result<()> {
        // Update existing.
        for slot in &mut self.caps {
            if slot.valid && slot.cap_id == cap.cap_id {
                slot.issued = cap.issued;
                slot.seq = cap.seq;
                return Ok(());
            }
        }
        // Insert into empty slot.
        for slot in &mut self.caps {
            if !slot.valid {
                *slot = cap;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Revoke the capability with the given `cap_id`.
    ///
    /// Returns `NotFound` if no matching cap exists.
    pub fn revoke(&mut self, cap_id: u64) -> Result<()> {
        for slot in &mut self.caps {
            if slot.valid && slot.cap_id == cap_id {
                *slot = CephCap::empty();
                self.count = self.count.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Check whether any cap grants the specified permission flag.
    pub fn has(&self, flag: u32) -> bool {
        self.caps.iter().any(|c| c.has(flag))
    }

    /// Return the merged `issued` bitfield across all caps.
    pub fn issued(&self) -> u32 {
        self.caps
            .iter()
            .filter(|c| c.valid)
            .fold(0, |acc, c| acc | c.issued)
    }

    /// Number of active caps.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for CapSet {
    fn default() -> Self {
        Self::new()
    }
}

// ── CephInode ────────────────────────────────────────────────────

/// A Ceph inode entry in the client inode cache.
///
/// Holds file metadata as returned by the MDS and the current capability
/// set for this client. Fields are refreshed on each `lookup` or `stat`
/// call.
#[derive(Debug, Clone, Copy)]
pub struct CephInode {
    /// Inode number.
    pub ino: u64,
    /// POSIX permission mode bits (includes file type bits).
    pub mode: u32,
    /// File size in bytes.
    pub size: u64,
    /// Last modification time (seconds since epoch).
    pub mtime: u64,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// Number of hard links.
    pub nlink: u32,
    /// Capability set for this inode.
    pub caps: CapSet,
    /// Cache generation counter (incremented on each update).
    pub lru_gen: u64,
    /// Whether this cache slot is occupied.
    pub valid: bool,
}

impl CephInode {
    /// Create an empty (invalid) inode slot.
    pub const fn empty() -> Self {
        Self {
            ino: 0,
            mode: 0,
            size: 0,
            mtime: 0,
            uid: 0,
            gid: 0,
            nlink: 0,
            caps: CapSet::new(),
            lru_gen: 0,
            valid: false,
        }
    }

    /// Create a new inode with the given parameters.
    pub fn new(ino: u64, mode: u32, size: u64, mtime: u64) -> Self {
        Self {
            ino,
            mode,
            size,
            mtime,
            uid: 0,
            gid: 0,
            nlink: 1,
            caps: CapSet::new(),
            lru_gen: 0,
            valid: true,
        }
    }

    /// Whether this inode is a regular file.
    pub fn is_file(&self) -> bool {
        (self.mode & 0xF000) == 0x8000
    }

    /// Whether this inode is a directory.
    pub fn is_dir(&self) -> bool {
        (self.mode & 0xF000) == 0x4000
    }
}

// ── InodeCache ───────────────────────────────────────────────────

/// LRU inode cache holding up to [`MAX_INODE_CACHE`] entries.
///
/// Eviction is by lowest `gen` (oldest). Each insertion increments the
/// global generation counter, making recently inserted entries the most
/// expensive to evict.
pub struct InodeCache {
    /// Cache slots.
    entries: [CephInode; MAX_INODE_CACHE],
    /// Global generation counter for LRU ordering.
    lru_gen: u64,
    /// Number of valid cache entries.
    count: usize,
}

impl InodeCache {
    /// Create a new empty inode cache.
    pub fn new() -> Self {
        Self {
            entries: [const { CephInode::empty() }; MAX_INODE_CACHE],
            lru_gen: 0,
            count: 0,
        }
    }

    /// Look up an inode by its number.
    ///
    /// Returns `None` if the inode is not cached.
    pub fn get(&self, ino: u64) -> Option<&CephInode> {
        self.entries.iter().find(|e| e.valid && e.ino == ino)
    }

    /// Look up an inode by its number and return a mutable reference.
    pub fn get_mut(&mut self, ino: u64) -> Option<&mut CephInode> {
        self.entries.iter_mut().find(|e| e.valid && e.ino == ino)
    }

    /// Insert or replace a cached inode.
    ///
    /// If the inode is already cached its entry is updated in place.
    /// Otherwise an empty or lowest-generation slot is evicted.
    pub fn insert(&mut self, mut inode: CephInode) {
        self.lru_gen = self.lru_gen.wrapping_add(1);
        inode.lru_gen = self.lru_gen;

        // Update existing entry.
        for slot in &mut self.entries {
            if slot.valid && slot.ino == inode.ino {
                *slot = inode;
                return;
            }
        }

        // Use an empty slot.
        for slot in &mut self.entries {
            if !slot.valid {
                *slot = inode;
                self.count += 1;
                return;
            }
        }

        // Evict lowest-generation entry (LRU).
        let mut lru_idx = 0;
        let mut lru_gen = u64::MAX;
        for (i, slot) in self.entries.iter().enumerate() {
            if slot.lru_gen < lru_gen {
                lru_gen = slot.lru_gen;
                lru_idx = i;
            }
        }
        self.entries[lru_idx] = inode;
    }

    /// Invalidate (remove) the cache entry for the given inode number.
    pub fn invalidate(&mut self, ino: u64) {
        for slot in &mut self.entries {
            if slot.valid && slot.ino == ino {
                *slot = CephInode::empty();
                self.count = self.count.saturating_sub(1);
                return;
            }
        }
    }

    /// Number of valid cache entries.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Whether the cache has no valid entries.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for InodeCache {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for InodeCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InodeCache")
            .field("count", &self.count)
            .field("gen", &self.lru_gen)
            .finish()
    }
}

// ── OsdOpType ────────────────────────────────────────────────────

/// OSD operation type selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsdOpType {
    /// Read object data.
    Read,
    /// Write object data.
    Write,
    /// Create an object.
    Create,
    /// Delete an object.
    Delete,
}

// ── OsdRequest ───────────────────────────────────────────────────

/// A request to an OSD (Object Storage Daemon).
///
/// Maps to a single RADOS object operation. The `oid` identifies the
/// object (encoded as a u64 for portability in no_std).
#[derive(Debug, Clone, Copy)]
pub struct OsdRequest {
    /// Operation type.
    pub op_type: OsdOpType,
    /// Object identifier.
    pub oid: u64,
    /// Byte offset within the object.
    pub offset: u64,
    /// Number of bytes to read or write.
    pub length: u32,
    /// Data payload (for write ops; zero for reads).
    pub data: [u8; MAX_OSD_DATA],
    /// Number of valid bytes in `data`.
    pub data_len: usize,
}

impl OsdRequest {
    /// Create a new read request.
    pub fn read(oid: u64, offset: u64, length: u32) -> Self {
        Self {
            op_type: OsdOpType::Read,
            oid,
            offset,
            length,
            data: [0u8; MAX_OSD_DATA],
            data_len: 0,
        }
    }

    /// Create a new write request.
    ///
    /// Copies up to `MAX_OSD_DATA` bytes from `data` into the request buffer.
    pub fn write(oid: u64, offset: u64, data: &[u8]) -> Self {
        let mut req = Self {
            op_type: OsdOpType::Write,
            oid,
            offset,
            length: data.len() as u32,
            data: [0u8; MAX_OSD_DATA],
            data_len: 0,
        };
        let copy_len = data.len().min(MAX_OSD_DATA);
        req.data[..copy_len].copy_from_slice(&data[..copy_len]);
        req.data_len = copy_len;
        req
    }
}

// ── OsdReply ─────────────────────────────────────────────────────

/// Reply from an OSD operation.
#[derive(Clone, Copy)]
pub struct OsdReply {
    /// Result code: 0 for success, negative errno on error.
    pub result: i32,
    /// Response data payload (for read ops).
    pub data: [u8; MAX_OSD_DATA],
    /// Number of valid bytes in `data`.
    pub data_len: usize,
}

impl OsdReply {
    /// Create an empty success reply.
    pub fn success() -> Self {
        Self {
            result: 0,
            data: [0u8; MAX_OSD_DATA],
            data_len: 0,
        }
    }

    /// Create an error reply.
    pub fn error(errno: i32) -> Self {
        Self {
            result: errno,
            data: [0u8; MAX_OSD_DATA],
            data_len: 0,
        }
    }

    /// Whether the reply indicates success.
    pub fn is_ok(&self) -> bool {
        self.result == 0
    }
}

impl core::fmt::Debug for OsdReply {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OsdReply")
            .field("result", &self.result)
            .field("data_len", &self.data_len)
            .finish()
    }
}

// ── OsdMap ───────────────────────────────────────────────────────

/// OSD cluster map (stub).
///
/// In a full Ceph implementation this would hold the CRUSH map and OSD
/// state bitmaps. This stub tracks only the epoch and a cluster id so
/// that the types are well-formed for integration.
#[derive(Debug, Clone, Copy)]
pub struct OsdMap {
    /// Cluster map epoch.
    pub epoch: u32,
    /// Cluster identifier (arbitrary u64).
    pub cluster_id: u64,
    /// Number of OSDs in the cluster (informational).
    pub osd_count: u32,
}

impl OsdMap {
    /// Create a new OSD map with the given parameters.
    pub fn new(epoch: u32, cluster_id: u64, osd_count: u32) -> Self {
        Self {
            epoch,
            cluster_id,
            osd_count,
        }
    }

    /// Create an empty placeholder OSD map.
    pub fn empty() -> Self {
        Self {
            epoch: 0,
            cluster_id: 0,
            osd_count: 0,
        }
    }
}

// ── CephFs ───────────────────────────────────────────────────────

/// Top-level Ceph FS client handle.
///
/// Manages the MDS session, inode cache, and OSD map. All VFS operations
/// route through this struct.
pub struct CephFs {
    /// MDS session state.
    pub mds_session: CephMdsSession,
    /// Local inode cache.
    pub inode_cache: InodeCache,
    /// OSD cluster map.
    pub osd_map: OsdMap,
}

impl CephFs {
    /// Create a new, disconnected CephFs client.
    pub fn new() -> Self {
        Self {
            mds_session: CephMdsSession::new(),
            inode_cache: InodeCache::new(),
            osd_map: OsdMap::empty(),
        }
    }

    /// Connect to the MDS at the given address.
    ///
    /// Transitions the MDS session to `Opening` and immediately confirms it
    /// as `Open` with a stub session id. In a real implementation this
    /// would involve sending an MDS session request via IPC and waiting for
    /// the reply.
    ///
    /// Returns `Busy` if already connected.
    pub fn connect_mds(&mut self, addr: u64) -> Result<()> {
        self.mds_session.open(addr)?;
        // Stub: confirm immediately with a synthetic session id.
        self.mds_session.confirm_open(addr ^ 0xCAFE_BABE, 1)?;
        Ok(())
    }

    /// Disconnect from the MDS.
    ///
    /// Returns `InvalidArgument` if the session is not open.
    pub fn disconnect_mds(&mut self) -> Result<()> {
        self.mds_session.close()?;
        self.mds_session.finalize_close();
        Ok(())
    }

    /// Look up a name in the given parent directory inode.
    ///
    /// Returns the child `CephInode` from the cache if present, or a
    /// synthesized stub inode representing a successful MDS LOOKUP reply.
    ///
    /// Returns `PermissionDenied` if the MDS session is not open.
    pub fn lookup(&mut self, parent_ino: u64, name: &str) -> Result<CephInode> {
        if !self.mds_session.is_open() {
            return Err(Error::PermissionDenied);
        }

        // Derive a synthetic inode number from parent + name hash.
        let name_hash = name.bytes().fold(parent_ino, |h, b| {
            h.wrapping_mul(0x9E37_9B97).wrapping_add(b as u64)
        });
        let child_ino = name_hash | 1; // ensure non-zero

        // Return cached inode if available.
        if let Some(cached) = self.inode_cache.get(child_ino) {
            return Ok(*cached);
        }

        // Stub: synthesize a regular-file inode.
        let inode = CephInode::new(child_ino, 0o10_0644, 0, 0);
        self.inode_cache.insert(inode);
        Ok(inode)
    }

    /// List entries in the directory identified by `ino`.
    ///
    /// Returns a fixed-size array of (inode_number, name_bytes) pairs.
    /// This is a stub that returns an empty list; a real implementation
    /// would issue an MDS READDIR request and cache the results.
    ///
    /// Returns `PermissionDenied` if the MDS session is not open, or
    /// `NotFound` if `ino` is not a directory.
    pub fn readdir(
        &mut self,
        ino: u64,
    ) -> Result<[(u64, [u8; MAX_NAME_LEN], usize); MAX_DIR_ENTRIES]> {
        if !self.mds_session.is_open() {
            return Err(Error::PermissionDenied);
        }

        // Validate that the inode is a directory if cached.
        if let Some(cached) = self.inode_cache.get(ino) {
            if !cached.is_dir() {
                return Err(Error::NotFound);
            }
        }

        // Stub: return empty listing (no MDS request infrastructure yet).
        let entries = [(0u64, [0u8; MAX_NAME_LEN], 0usize); MAX_DIR_ENTRIES];
        Ok(entries)
    }

    /// Read data from a Ceph file.
    ///
    /// Issues an OSD read request for the object(s) backing `ino`.
    /// In this stub the object-to-OSD mapping is not implemented; the
    /// function returns `NotImplemented` to signal that IPC to an OSD
    /// is required.
    ///
    /// Returns `PermissionDenied` if the session is not open or if the
    /// inode's cap set does not include `READ`. Returns `NotFound` if
    /// the inode is not in the cache.
    pub fn read(&mut self, ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if !self.mds_session.is_open() {
            return Err(Error::PermissionDenied);
        }

        let has_read_cap = self
            .inode_cache
            .get(ino)
            .map(|i| i.caps.has(CapFlags::READ))
            .unwrap_or(false);

        if !has_read_cap {
            // Request READ cap from MDS (stub: grant it directly).
            let cap = CephCap::new(ino, ino ^ 0x0001, CapFlags::READ | CapFlags::CACHE);
            if let Some(inode) = self.inode_cache.get_mut(ino) {
                inode.caps.insert(cap)?;
            } else {
                return Err(Error::NotFound);
            }
        }

        let _req = OsdRequest::read(ino, offset, buf.len() as u32);
        // Stub: OSD dispatch not yet wired; return NotImplemented so the
        // caller knows to route via IPC.
        Err(Error::NotImplemented)
    }

    /// Write data to a Ceph file.
    ///
    /// Constructs an OSD write request. As with [`read`](Self::read), the
    /// actual OSD dispatch requires IPC support not yet present in no_std.
    ///
    /// Returns `PermissionDenied` if write caps are not held.
    pub fn write(&mut self, ino: u64, offset: u64, data: &[u8]) -> Result<usize> {
        if !self.mds_session.is_open() {
            return Err(Error::PermissionDenied);
        }

        let has_write_cap = self
            .inode_cache
            .get(ino)
            .map(|i| i.caps.has(CapFlags::WRITE))
            .unwrap_or(false);

        if !has_write_cap {
            // Request WRITE cap from MDS (stub: grant directly).
            let cap = CephCap::new(ino, ino ^ 0x0002, CapFlags::WRITE | CapFlags::EXCL);
            if let Some(inode) = self.inode_cache.get_mut(ino) {
                inode.caps.insert(cap)?;
            } else {
                return Err(Error::NotFound);
            }
        }

        let copy_len = data.len().min(MAX_OSD_DATA);
        let _req = OsdRequest::write(ino, offset, &data[..copy_len]);
        // Stub: OSD dispatch not yet wired.
        Err(Error::NotImplemented)
    }

    /// Update the OSD map to a new epoch.
    pub fn update_osd_map(&mut self, osd_map: OsdMap) {
        self.osd_map = osd_map;
    }

    /// Grant capabilities on an inode (called when an MDS cap message arrives).
    ///
    /// Returns `NotFound` if the inode is not cached.
    pub fn grant_caps(&mut self, cap: CephCap) -> Result<()> {
        if let Some(inode) = self.inode_cache.get_mut(cap.ino) {
            inode.caps.insert(cap)
        } else {
            Err(Error::NotFound)
        }
    }

    /// Revoke a capability on an inode (called when the MDS sends REVOKE).
    ///
    /// Returns `NotFound` if the inode or cap is not cached.
    pub fn revoke_cap(&mut self, ino: u64, cap_id: u64) -> Result<()> {
        if let Some(inode) = self.inode_cache.get_mut(ino) {
            inode.caps.revoke(cap_id)
        } else {
            Err(Error::NotFound)
        }
    }
}

impl Default for CephFs {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for CephFs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CephFs")
            .field("mds_session", &self.mds_session)
            .field("inode_cache", &self.inode_cache)
            .field("osd_map", &self.osd_map)
            .finish()
    }
}
