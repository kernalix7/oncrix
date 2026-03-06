// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NFS (Network File System) client implementation.
//!
//! Provides a minimal NFS client supporting NFS v3, v4, and v4.1 protocol
//! structures. The client translates VFS operations into NFS RPC calls
//! and caches file attributes for reduced network round-trips.
//!
//! # Architecture
//!
//! ```text
//! VFS operation
//!   → NfsClient::lookup() / read() / write()
//!     → build NfsRpcHeader + procedure args
//!       → send to server_addr via IPC/network
//!         → parse reply + update NfsCache
//!           → return result to VFS caller
//! ```
//!
//! # Structures
//!
//! - [`NfsVersion`] — protocol version selector (V3, V4, V4_1)
//! - [`NfsFileHandle`] — 128-byte opaque file handle
//! - [`NfsAttr`] — cached file attributes (type, mode, uid, gid, size, times)
//! - [`NfsRpcHeader`] — Sun RPC header for NFS calls/replies
//! - [`NfsProcedure`] — NFS procedure codes (Null, Getattr, Read, Write, etc.)
//! - [`NfsClient`] — stateful NFS client with mount, lookup, read, write
//! - [`NfsCache`] — 128-entry attribute cache with TTL-based expiry
//! - [`NfsRegistry`] — global registry of NFS mounts (8 slots)

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Size of an NFS file handle in bytes.
const NFS_FH_SIZE: usize = 128;

/// Maximum mount path length in bytes.
const MAX_MOUNT_PATH: usize = 256;

/// Maximum number of cache entries.
const MAX_CACHE_ENTRIES: usize = 128;

/// Default attribute cache TTL in ticks.
const DEFAULT_CACHE_TTL: u64 = 300;

/// Maximum number of NFS mounts in the registry.
const MAX_NFS_MOUNTS: usize = 8;

/// NFS program number for Sun RPC.
const NFS_PROGRAM: u32 = 100003;

/// Standard RPC version.
const RPC_VERSION: u32 = 2;

// ── NfsVersion ──────────────────────────────────────────────────

/// NFS protocol version.
///
/// Selects which version of the NFS protocol the client should speak.
/// Each version has different wire formats and capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfsVersion {
    /// NFS version 3 — stateless, uses separate MOUNT protocol.
    V3,
    /// NFS version 4 — stateful, compound operations, integrated MOUNT.
    V4,
    /// NFS version 4.1 — sessions, pNFS, directory delegation.
    V4_1,
}

impl NfsVersion {
    /// Return the numeric version for RPC headers.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::V3 => 3,
            Self::V4 => 4,
            Self::V4_1 => 41,
        }
    }
}

// ── NfsFileHandle ───────────────────────────────────────────────

/// Opaque NFS file handle.
///
/// A 128-byte opaque identifier that the NFS server uses to locate
/// a file or directory. Handles are returned by MOUNT and LOOKUP
/// operations and are passed back to the server in subsequent calls.
#[derive(Clone, Copy)]
pub struct NfsFileHandle {
    /// Raw handle bytes.
    data: [u8; NFS_FH_SIZE],
    /// Number of valid bytes in `data`.
    len: usize,
}

impl NfsFileHandle {
    /// Create a new empty file handle.
    pub fn empty() -> Self {
        Self {
            data: [0u8; NFS_FH_SIZE],
            len: 0,
        }
    }

    /// Create a file handle from a byte slice.
    ///
    /// Returns `InvalidArgument` if `bytes` exceeds the maximum handle size.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > NFS_FH_SIZE {
            return Err(Error::InvalidArgument);
        }
        let mut fh = Self::empty();
        fh.data[..bytes.len()].copy_from_slice(bytes);
        fh.len = bytes.len();
        Ok(fh)
    }

    /// Return the valid portion of the handle as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Return the length of the valid handle data.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the handle is empty (zero-length).
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl core::fmt::Debug for NfsFileHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NfsFileHandle")
            .field("len", &self.len)
            .finish()
    }
}

impl PartialEq for NfsFileHandle {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for NfsFileHandle {}

// ── NfsFileType ─────────────────────────────────────────────────

/// NFS file type from attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfsFileType {
    /// Regular file.
    Regular,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
    /// Special file (block device, char device, FIFO, socket).
    Special,
}

// ── NfsAttr ─────────────────────────────────────────────────────

/// NFS file attributes.
///
/// Represents the attributes of a remote file as returned by GETATTR
/// or carried along with other NFS replies. These are cached locally
/// and refreshed when the TTL expires.
#[derive(Debug, Clone, Copy)]
pub struct NfsAttr {
    /// File type (regular, directory, symlink, special).
    pub file_type: NfsFileType,
    /// POSIX permission mode bits.
    pub mode: u32,
    /// Number of hard links.
    pub nlink: u32,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// File size in bytes.
    pub size: u64,
    /// Last access time (seconds since epoch).
    pub atime: u64,
    /// Last modification time (seconds since epoch).
    pub mtime: u64,
    /// Last status change time (seconds since epoch).
    pub ctime: u64,
}

impl NfsAttr {
    /// Create a default attribute set for a directory.
    pub fn default_dir() -> Self {
        Self {
            file_type: NfsFileType::Directory,
            mode: 0o755,
            nlink: 2,
            uid: 0,
            gid: 0,
            size: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
        }
    }

    /// Create a default attribute set for a regular file.
    pub fn default_file() -> Self {
        Self {
            file_type: NfsFileType::Regular,
            mode: 0o644,
            nlink: 1,
            uid: 0,
            gid: 0,
            size: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
        }
    }
}

// ── NfsRpcHeader ────────────────────────────────────────────────

/// RPC message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RpcMsgType {
    /// RPC call (client → server).
    Call = 0,
    /// RPC reply (server → client).
    Reply = 1,
}

/// Sun RPC header for NFS requests and responses.
///
/// Follows the XDR-encoded ONC RPC header format. Each NFS operation
/// is wrapped in an RPC call with this header.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct NfsRpcHeader {
    /// Transaction identifier (unique per call).
    pub xid: u32,
    /// Message type (0 = Call, 1 = Reply).
    pub msg_type: u32,
    /// RPC version (always 2).
    pub rpc_version: u32,
    /// RPC program number (100003 for NFS).
    pub program: u32,
    /// Program version (3 for NFSv3, 4 for NFSv4).
    pub version: u32,
    /// Procedure number within the program.
    pub procedure: u32,
}

impl NfsRpcHeader {
    /// Build a new RPC call header for an NFS procedure.
    pub fn new_call(xid: u32, version: NfsVersion, procedure: NfsProcedure) -> Self {
        Self {
            xid,
            msg_type: RpcMsgType::Call as u32,
            rpc_version: RPC_VERSION,
            program: NFS_PROGRAM,
            version: version.as_u32(),
            procedure: procedure.as_u32(),
        }
    }

    /// Check whether this header represents a call message.
    pub fn is_call(&self) -> bool {
        self.msg_type == RpcMsgType::Call as u32
    }

    /// Check whether this header represents a reply message.
    pub fn is_reply(&self) -> bool {
        self.msg_type == RpcMsgType::Reply as u32
    }

    /// Validate the header fields.
    pub fn validate(&self) -> Result<()> {
        if self.rpc_version != RPC_VERSION {
            return Err(Error::InvalidArgument);
        }
        if self.program != NFS_PROGRAM {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ── NfsProcedure ────────────────────────────────────────────────

/// NFS remote procedure identifiers.
///
/// Each variant corresponds to an NFS protocol operation. The numeric
/// values follow the NFSv3 procedure numbering convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfsProcedure {
    /// NULL — no-op ping to test connectivity.
    Null,
    /// GETATTR — get file attributes.
    Getattr,
    /// SETATTR — set file attributes.
    Setattr,
    /// LOOKUP — look up filename in a directory.
    Lookup,
    /// READ — read data from a file.
    Read,
    /// WRITE — write data to a file.
    Write,
    /// CREATE — create a regular file.
    Create,
    /// REMOVE — remove a file.
    Remove,
    /// MKDIR — create a directory.
    Mkdir,
    /// RMDIR — remove a directory.
    Rmdir,
    /// READDIR — read directory entries.
    Readdir,
}

impl NfsProcedure {
    /// Return the numeric procedure code.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::Null => 0,
            Self::Getattr => 1,
            Self::Setattr => 2,
            Self::Lookup => 3,
            Self::Read => 6,
            Self::Write => 7,
            Self::Create => 8,
            Self::Remove => 12,
            Self::Mkdir => 9,
            Self::Rmdir => 13,
            Self::Readdir => 16,
        }
    }

    /// Try to parse a procedure code from its numeric value.
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Null),
            1 => Some(Self::Getattr),
            2 => Some(Self::Setattr),
            3 => Some(Self::Lookup),
            6 => Some(Self::Read),
            7 => Some(Self::Write),
            8 => Some(Self::Create),
            9 => Some(Self::Mkdir),
            12 => Some(Self::Remove),
            13 => Some(Self::Rmdir),
            16 => Some(Self::Readdir),
            _ => None,
        }
    }
}

// ── NfsClient ───────────────────────────────────────────────────

/// NFS client instance.
///
/// Manages a connection to a single NFS server, maintaining state
/// such as the root file handle, protocol version, and XID counter
/// for correlating RPC calls and replies.
pub struct NfsClient {
    /// Server IP address (as a u32 for simplicity in no_std).
    server_addr: u32,
    /// Remote export path.
    mount_path: [u8; MAX_MOUNT_PATH],
    /// Length of valid bytes in `mount_path`.
    mount_path_len: usize,
    /// Root file handle obtained from the MOUNT procedure.
    root_handle: NfsFileHandle,
    /// NFS protocol version in use.
    version: NfsVersion,
    /// Next transaction ID for RPC calls.
    next_xid: u32,
    /// Whether the client is currently mounted.
    mounted: bool,
}

impl NfsClient {
    /// Create a new NFS client targeting the given server.
    ///
    /// The client is initially unmounted. Call [`mount`](Self::mount)
    /// to establish the connection and obtain the root file handle.
    pub fn new(server_addr: u32, version: NfsVersion) -> Self {
        Self {
            server_addr,
            mount_path: [0u8; MAX_MOUNT_PATH],
            mount_path_len: 0,
            root_handle: NfsFileHandle::empty(),
            version,
            next_xid: 1,
            mounted: false,
        }
    }

    /// Mount the remote export path.
    ///
    /// Stores the mount path and sets the root handle. In a real
    /// implementation this would issue an RPC MOUNT call to the server.
    pub fn mount(&mut self, path: &[u8], root_handle: NfsFileHandle) -> Result<()> {
        if path.len() > MAX_MOUNT_PATH {
            return Err(Error::InvalidArgument);
        }
        if self.mounted {
            return Err(Error::Busy);
        }
        self.mount_path[..path.len()].copy_from_slice(path);
        self.mount_path_len = path.len();
        self.root_handle = root_handle;
        self.mounted = true;
        Ok(())
    }

    /// Return the server address.
    pub fn server_addr(&self) -> u32 {
        self.server_addr
    }

    /// Return the NFS version in use.
    pub fn version(&self) -> NfsVersion {
        self.version
    }

    /// Whether the client is mounted.
    pub fn is_mounted(&self) -> bool {
        self.mounted
    }

    /// Return a reference to the root file handle.
    pub fn root_handle(&self) -> &NfsFileHandle {
        &self.root_handle
    }

    /// Allocate the next XID and build an RPC header.
    fn next_header(&mut self, procedure: NfsProcedure) -> NfsRpcHeader {
        let xid = self.next_xid;
        self.next_xid = self.next_xid.wrapping_add(1);
        NfsRpcHeader::new_call(xid, self.version, procedure)
    }

    /// Look up a name within a directory identified by its file handle.
    ///
    /// Returns the file handle and attributes for the named entry.
    /// In a real implementation this sends LOOKUP to the server.
    pub fn lookup(
        &mut self,
        dir_handle: &NfsFileHandle,
        name: &[u8],
    ) -> Result<(NfsFileHandle, NfsAttr)> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        if name.is_empty() || dir_handle.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let _header = self.next_header(NfsProcedure::Lookup);
        // Stub: a real implementation would serialize dir_handle + name,
        // send the RPC, and parse the reply. Return NotFound for now.
        Err(Error::NotImplemented)
    }

    /// Read data from a remote file.
    ///
    /// Reads up to `buf.len()` bytes starting at `offset` from the file
    /// identified by `handle`. Returns the number of bytes read.
    pub fn read(&mut self, handle: &NfsFileHandle, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        if handle.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let _header = self.next_header(NfsProcedure::Read);
        let _ = offset;
        let _ = buf;
        // Stub: would serialize handle + offset + count, send RPC, copy reply data.
        Err(Error::NotImplemented)
    }

    /// Write data to a remote file.
    ///
    /// Writes `data` starting at `offset` in the file identified by
    /// `handle`. Returns the number of bytes written.
    pub fn write(&mut self, handle: &NfsFileHandle, offset: u64, data: &[u8]) -> Result<usize> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        if handle.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let _header = self.next_header(NfsProcedure::Write);
        let _ = offset;
        let _ = data;
        // Stub: would serialize handle + offset + data, send RPC.
        Err(Error::NotImplemented)
    }

    /// Get attributes for a remote file.
    pub fn getattr(&mut self, handle: &NfsFileHandle) -> Result<NfsAttr> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        if handle.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let _header = self.next_header(NfsProcedure::Getattr);
        // Stub: would send GETATTR RPC and parse reply.
        Err(Error::NotImplemented)
    }

    /// Set attributes on a remote file.
    pub fn setattr(&mut self, handle: &NfsFileHandle, attr: &NfsAttr) -> Result<()> {
        if !self.mounted {
            return Err(Error::InvalidArgument);
        }
        if handle.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let _header = self.next_header(NfsProcedure::Setattr);
        let _ = attr;
        // Stub: would serialize handle + new attrs, send RPC.
        Err(Error::NotImplemented)
    }
}

impl core::fmt::Debug for NfsClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NfsClient")
            .field("server_addr", &self.server_addr)
            .field("version", &self.version)
            .field("mounted", &self.mounted)
            .field("next_xid", &self.next_xid)
            .finish()
    }
}

// ── NfsCache ────────────────────────────────────────────────────

/// A single cache entry mapping a file handle to its attributes.
#[derive(Clone)]
struct NfsCacheEntry {
    /// File handle (key).
    handle: NfsFileHandle,
    /// Cached attributes (value).
    attr: NfsAttr,
    /// Tick at which this entry was inserted.
    insert_tick: u64,
    /// Whether this slot is occupied.
    valid: bool,
}

impl NfsCacheEntry {
    const fn empty() -> Self {
        Self {
            handle: NfsFileHandle {
                data: [0u8; NFS_FH_SIZE],
                len: 0,
            },
            attr: NfsAttr {
                file_type: NfsFileType::Regular,
                mode: 0,
                nlink: 0,
                uid: 0,
                gid: 0,
                size: 0,
                atime: 0,
                mtime: 0,
                ctime: 0,
            },
            insert_tick: 0,
            valid: false,
        }
    }
}

impl Default for NfsCache {
    fn default() -> Self {
        Self::new()
    }
}

/// NFS attribute cache.
///
/// Caches file attributes keyed by file handle. Entries expire after
/// a configurable TTL (default 300 ticks). The cache uses a fixed-size
/// array with linear probing for simplicity.
pub struct NfsCache {
    /// Cache entries.
    entries: [NfsCacheEntry; MAX_CACHE_ENTRIES],
    /// TTL in ticks before an entry expires.
    ttl: u64,
    /// Number of valid entries.
    count: usize,
}

impl NfsCache {
    /// Create a new empty cache with the default TTL.
    pub fn new() -> Self {
        Self {
            entries: [const { NfsCacheEntry::empty() }; MAX_CACHE_ENTRIES],
            ttl: DEFAULT_CACHE_TTL,
            count: 0,
        }
    }

    /// Create a new cache with a custom TTL.
    pub fn with_ttl(ttl: u64) -> Self {
        Self {
            entries: [const { NfsCacheEntry::empty() }; MAX_CACHE_ENTRIES],
            ttl,
            count: 0,
        }
    }

    /// Look up attributes for a file handle.
    ///
    /// Returns `None` if the handle is not cached or the entry has expired.
    pub fn lookup(&self, handle: &NfsFileHandle, current_tick: u64) -> Option<&NfsAttr> {
        for entry in &self.entries {
            if entry.valid
                && entry.handle == *handle
                && current_tick.saturating_sub(entry.insert_tick) < self.ttl
            {
                return Some(&entry.attr);
            }
        }
        None
    }

    /// Insert or update a cache entry for the given handle.
    ///
    /// If the cache is full and no expired entries can be reclaimed,
    /// the oldest entry is evicted.
    pub fn insert(
        &mut self,
        handle: NfsFileHandle,
        attr: NfsAttr,
        current_tick: u64,
    ) -> Result<()> {
        // Update existing entry if present.
        for entry in &mut self.entries {
            if entry.valid && entry.handle == handle {
                entry.attr = attr;
                entry.insert_tick = current_tick;
                return Ok(());
            }
        }

        // Find an empty or expired slot.
        for entry in &mut self.entries {
            if !entry.valid || current_tick.saturating_sub(entry.insert_tick) >= self.ttl {
                if !entry.valid {
                    self.count += 1;
                }
                entry.handle = handle;
                entry.attr = attr;
                entry.insert_tick = current_tick;
                entry.valid = true;
                return Ok(());
            }
        }

        // Evict the oldest entry.
        let mut oldest_idx = 0;
        let mut oldest_tick = u64::MAX;
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.valid && entry.insert_tick < oldest_tick {
                oldest_tick = entry.insert_tick;
                oldest_idx = i;
            }
        }
        self.entries[oldest_idx].handle = handle;
        self.entries[oldest_idx].attr = attr;
        self.entries[oldest_idx].insert_tick = current_tick;
        self.entries[oldest_idx].valid = true;
        Ok(())
    }

    /// Invalidate (remove) the cache entry for a file handle.
    pub fn invalidate(&mut self, handle: &NfsFileHandle) {
        for entry in &mut self.entries {
            if entry.valid && entry.handle == *handle {
                entry.valid = false;
                self.count = self.count.saturating_sub(1);
                return;
            }
        }
    }

    /// Remove all entries whose TTL has expired.
    pub fn evict_expired(&mut self, current_tick: u64) {
        for entry in &mut self.entries {
            if entry.valid && current_tick.saturating_sub(entry.insert_tick) >= self.ttl {
                entry.valid = false;
                self.count = self.count.saturating_sub(1);
            }
        }
    }

    /// Number of valid (non-expired) entries currently in the cache.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl core::fmt::Debug for NfsCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NfsCache")
            .field("count", &self.count)
            .field("ttl", &self.ttl)
            .finish()
    }
}

// ── NfsRegistry ─────────────────────────────────────────────────

/// An NFS mount entry in the registry.
struct NfsMountEntry {
    /// Mount path in the local VFS namespace.
    path: [u8; MAX_MOUNT_PATH],
    /// Length of valid bytes in `path`.
    path_len: usize,
    /// The NFS client for this mount.
    client: NfsClient,
    /// Attribute cache for this mount.
    cache: NfsCache,
    /// Whether this slot is occupied.
    active: bool,
}

impl Default for NfsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Global registry of NFS mount points.
///
/// Tracks up to 8 active NFS mounts, each with its own client
/// connection and attribute cache.
pub struct NfsRegistry {
    /// Mount entries.
    mounts: [NfsMountEntry; MAX_NFS_MOUNTS],
    /// Number of active mounts.
    count: usize,
}

impl NfsRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            mounts: core::array::from_fn(|_| NfsMountEntry {
                path: [0u8; MAX_MOUNT_PATH],
                path_len: 0,
                client: NfsClient::new(0, NfsVersion::V3),
                cache: NfsCache::new(),
                active: false,
            }),
            count: 0,
        }
    }

    /// Mount an NFS export at the given local path.
    ///
    /// Returns `OutOfMemory` if the registry is full, or `AlreadyExists`
    /// if the path is already mounted.
    pub fn mount(&mut self, path: &[u8], client: NfsClient) -> Result<usize> {
        if path.len() > MAX_MOUNT_PATH {
            return Err(Error::InvalidArgument);
        }

        // Check for duplicate mount path.
        for entry in &self.mounts {
            if entry.active && entry.path_len == path.len() && entry.path[..path.len()] == *path {
                return Err(Error::AlreadyExists);
            }
        }

        // Find a free slot.
        for (i, entry) in self.mounts.iter_mut().enumerate() {
            if !entry.active {
                entry.path[..path.len()].copy_from_slice(path);
                entry.path_len = path.len();
                entry.client = client;
                entry.cache = NfsCache::new();
                entry.active = true;
                self.count += 1;
                return Ok(i);
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Unmount the NFS export at the given local path.
    pub fn unmount(&mut self, path: &[u8]) -> Result<()> {
        for entry in &mut self.mounts {
            if entry.active && entry.path_len == path.len() && entry.path[..path.len()] == *path {
                entry.active = false;
                self.count = self.count.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Find a mount by its local path.
    ///
    /// Returns a reference to the NFS client if found.
    pub fn find_by_path(&self, path: &[u8]) -> Option<&NfsClient> {
        for entry in &self.mounts {
            if entry.active && entry.path_len == path.len() && entry.path[..path.len()] == *path {
                return Some(&entry.client);
            }
        }
        None
    }

    /// Find a mount by path and return a mutable reference to the client.
    pub fn find_by_path_mut(&mut self, path: &[u8]) -> Option<&mut NfsClient> {
        for entry in &mut self.mounts {
            if entry.active && entry.path_len == path.len() && entry.path[..path.len()] == *path {
                return Some(&mut entry.client);
            }
        }
        None
    }

    /// Number of active NFS mounts.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl core::fmt::Debug for NfsRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NfsRegistry")
            .field("count", &self.count)
            .finish()
    }
}
