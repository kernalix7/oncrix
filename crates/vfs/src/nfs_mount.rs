// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NFS mount and unmount operations.
//!
//! Implements the client-side NFS mount/unmount lifecycle:
//!
//! - [`NfsMountInfo`] — server address, export path, NFS version, flags
//! - [`NfsSuperblock`] — in-memory superblock for a mounted NFS export
//! - `mount_nfs` — create superblock, negotiate server, set root dentry
//! - `nfs_umount` — flush dirty pages, destroy the superblock
//!
//! # NFS Versions
//!
//! Both NFSv3 (UDP/TCP) and NFSv4 (TCP-only) are supported at the
//! mount/unmount level. Version negotiation happens during mount.
//!
//! # Reference
//!
//! Linux `fs/nfs/super.c`, `fs/nfs/client.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum NFS server address length (IPv4/IPv6 string).
const MAX_ADDR_LEN: usize = 64;

/// Maximum export path length.
const MAX_EXPORT_PATH: usize = 256;

/// Maximum number of simultaneously mounted NFS exports.
const MAX_NFS_MOUNTS: usize = 16;

/// Default NFS read size.
const NFS_DEFAULT_RSIZE: u32 = 131072;

/// Default NFS write size.
const NFS_DEFAULT_WSIZE: u32 = 131072;

/// Default RPC timeout in milliseconds.
const NFS_DEFAULT_TIMEOUT_MS: u32 = 60000;

/// NFS root file handle size (NFSv3 = 64 bytes, NFSv4 = 128 bytes).
const NFS_FHANDLE_SIZE: usize = 128;

// ---------------------------------------------------------------------------
// NFS version
// ---------------------------------------------------------------------------

/// NFS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfsVersion {
    /// NFSv3 (RFC 1813).
    V3,
    /// NFSv4 (RFC 7530).
    V4,
    /// NFSv4.1 with sessions (RFC 5661).
    V41,
}

impl NfsVersion {
    /// Returns whether this version requires TCP.
    pub fn requires_tcp(&self) -> bool {
        !matches!(self, Self::V3)
    }

    /// Returns the default port for this version.
    pub fn default_port(&self) -> u16 {
        2049
    }

    /// Returns the program number for this version.
    pub fn program_number(&self) -> u32 {
        100003
    }

    /// Returns the RPC version number.
    pub fn rpc_version(&self) -> u32 {
        match self {
            Self::V3 => 3,
            Self::V4 | Self::V41 => 4,
        }
    }
}

// ---------------------------------------------------------------------------
// Mount flags
// ---------------------------------------------------------------------------

/// NFS mount option flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct MountFlags(pub u32);

impl MountFlags {
    /// Read-only mount.
    pub const RO: u32 = 1 << 0;
    /// Hard mount (retry indefinitely on server failure).
    pub const HARD: u32 = 1 << 1;
    /// Soft mount (return error after timeout).
    pub const SOFT: u32 = 1 << 2;
    /// Allow interrupts to kill NFS requests.
    pub const INTR: u32 = 1 << 3;
    /// Enable synchronous writes.
    pub const SYNC: u32 = 1 << 4;
    /// Don't check server-side file locking.
    pub const NOLOCK: u32 = 1 << 5;
    /// Use POSIX ACL support.
    pub const POSIX_ACL: u32 = 1 << 6;
    /// Enable attribute caching.
    pub const ACREGMIN: u32 = 1 << 7;

    /// Returns whether read-only flag is set.
    pub fn is_ro(&self) -> bool {
        self.0 & Self::RO != 0
    }

    /// Returns whether hard mount is requested.
    pub fn is_hard(&self) -> bool {
        self.0 & Self::HARD != 0
    }

    /// Returns whether soft mount is requested.
    pub fn is_soft(&self) -> bool {
        self.0 & Self::SOFT != 0
    }
}

// ---------------------------------------------------------------------------
// Mount info
// ---------------------------------------------------------------------------

/// NFS mount parameters provided by userspace.
#[derive(Debug, Clone)]
pub struct NfsMountInfo {
    /// Server IP address or hostname (as string).
    pub server_addr: [u8; MAX_ADDR_LEN],
    /// Length of server_addr string.
    pub addr_len: usize,
    /// Export path on the server.
    pub export_path: [u8; MAX_EXPORT_PATH],
    /// Length of export_path string.
    pub path_len: usize,
    /// NFS version to use.
    pub version: NfsVersion,
    /// Mount option flags.
    pub flags: MountFlags,
    /// Read buffer size.
    pub rsize: u32,
    /// Write buffer size.
    pub wsize: u32,
    /// RPC timeout (milliseconds).
    pub timeo: u32,
    /// Number of retransmissions before failure.
    pub retrans: u32,
    /// Server port (0 = use default).
    pub port: u16,
}

impl NfsMountInfo {
    /// Creates a new mount info with defaults.
    pub fn new(version: NfsVersion) -> Self {
        Self {
            server_addr: [0u8; MAX_ADDR_LEN],
            addr_len: 0,
            export_path: [0u8; MAX_EXPORT_PATH],
            path_len: 0,
            version,
            flags: MountFlags::default(),
            rsize: NFS_DEFAULT_RSIZE,
            wsize: NFS_DEFAULT_WSIZE,
            timeo: NFS_DEFAULT_TIMEOUT_MS,
            retrans: 5,
            port: 0,
        }
    }

    /// Sets the server address from a byte slice.
    pub fn set_server_addr(&mut self, addr: &[u8]) -> Result<()> {
        if addr.len() > MAX_ADDR_LEN {
            return Err(Error::InvalidArgument);
        }
        self.server_addr[..addr.len()].copy_from_slice(addr);
        self.addr_len = addr.len();
        Ok(())
    }

    /// Sets the export path from a byte slice.
    pub fn set_export_path(&mut self, path: &[u8]) -> Result<()> {
        if path.len() > MAX_EXPORT_PATH {
            return Err(Error::InvalidArgument);
        }
        self.export_path[..path.len()].copy_from_slice(path);
        self.path_len = path.len();
        Ok(())
    }

    /// Returns the server address as a byte slice.
    pub fn server_addr_str(&self) -> &[u8] {
        &self.server_addr[..self.addr_len]
    }

    /// Returns the export path as a byte slice.
    pub fn export_path_str(&self) -> &[u8] {
        &self.export_path[..self.path_len]
    }

    /// Returns the effective port (default if port == 0).
    pub fn effective_port(&self) -> u16 {
        if self.port == 0 {
            self.version.default_port()
        } else {
            self.port
        }
    }

    /// Validates mount info fields.
    pub fn validate(&self) -> Result<()> {
        if self.addr_len == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.path_len == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.rsize == 0 || self.wsize == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.flags.is_hard() && self.flags.is_soft() {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// NFS file handle
// ---------------------------------------------------------------------------

/// An NFS file handle (opaque server-side identifier).
#[derive(Debug, Clone, Copy)]
pub struct NfsFileHandle {
    /// Raw file handle data.
    pub data: [u8; NFS_FHANDLE_SIZE],
    /// Valid bytes in data.
    pub len: usize,
}

impl NfsFileHandle {
    /// Creates a new file handle.
    pub const fn new() -> Self {
        Self {
            data: [0u8; NFS_FHANDLE_SIZE],
            len: 0,
        }
    }

    /// Copies file handle data from a slice.
    pub fn set(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > NFS_FHANDLE_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.data[..data.len()].copy_from_slice(data);
        self.len = data.len();
        Ok(())
    }
}

impl Default for NfsFileHandle {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// NFS superblock
// ---------------------------------------------------------------------------

/// In-memory superblock for a mounted NFS export.
#[derive(Debug)]
pub struct NfsSuperblock {
    /// Mount info used to create this superblock.
    pub mount_info: NfsMountInfo,
    /// Root directory file handle.
    pub root_fh: NfsFileHandle,
    /// Superblock flags.
    pub flags: u32,
    /// Whether the superblock has been mounted.
    pub mounted: bool,
    /// Whether dirty page flush is needed on unmount.
    pub dirty: bool,
    /// Mount ID (index in the global mount table).
    pub mount_id: u32,
    /// Total number of pages cached for this mount.
    pub cached_pages: u64,
    /// RPC call statistics.
    pub rpc_calls: u64,
    /// Number of read errors encountered.
    pub read_errors: u64,
    /// Number of write errors encountered.
    pub write_errors: u64,
}

impl NfsSuperblock {
    /// Creates a new unmounted NFS superblock.
    pub fn new(info: NfsMountInfo, mount_id: u32) -> Self {
        Self {
            mount_info: info,
            root_fh: NfsFileHandle::new(),
            flags: 0,
            mounted: false,
            dirty: false,
            mount_id,
            cached_pages: 0,
            rpc_calls: 0,
            read_errors: 0,
            write_errors: 0,
        }
    }

    /// Returns whether the superblock is read-only.
    pub fn is_ro(&self) -> bool {
        self.mount_info.flags.is_ro()
    }

    /// Marks the superblock as dirty (has unflushed writes).
    pub fn mark_dirty(&mut self) {
        if !self.is_ro() {
            self.dirty = true;
        }
    }

    /// Returns statistics about this superblock.
    pub fn stats(&self) -> NfsSuperblockStats {
        NfsSuperblockStats {
            mount_id: self.mount_id,
            mounted: self.mounted,
            dirty: self.dirty,
            cached_pages: self.cached_pages,
            rpc_calls: self.rpc_calls,
            read_errors: self.read_errors,
            write_errors: self.write_errors,
        }
    }
}

/// NFS superblock statistics.
#[derive(Debug, Clone, Copy)]
pub struct NfsSuperblockStats {
    /// Mount ID.
    pub mount_id: u32,
    /// Whether mounted.
    pub mounted: bool,
    /// Whether dirty.
    pub dirty: bool,
    /// Cached pages count.
    pub cached_pages: u64,
    /// Total RPC calls.
    pub rpc_calls: u64,
    /// Total read errors.
    pub read_errors: u64,
    /// Total write errors.
    pub write_errors: u64,
}

// ---------------------------------------------------------------------------
// Mount table
// ---------------------------------------------------------------------------

/// Global NFS mount table.
pub struct NfsMountTable {
    /// Active NFS superblocks.
    mounts: [Option<NfsSuperblock>; MAX_NFS_MOUNTS],
    /// Number of active mounts.
    count: usize,
    /// Next mount ID.
    next_id: u32,
}

impl NfsMountTable {
    /// Creates an empty mount table.
    pub const fn new() -> Self {
        Self {
            mounts: [
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None,
            ],
            count: 0,
            next_id: 1,
        }
    }

    /// Returns the number of active mounts.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Looks up a mount by ID.
    pub fn get(&self, id: u32) -> Option<&NfsSuperblock> {
        self.mounts.iter().flatten().find(|m| m.mount_id == id)
    }

    /// Mutably looks up a mount by ID.
    pub fn get_mut(&mut self, id: u32) -> Option<&mut NfsSuperblock> {
        self.mounts.iter_mut().flatten().find(|m| m.mount_id == id)
    }

    /// Inserts a new superblock into the table. Returns the mount ID.
    fn insert(&mut self, mut sb: NfsSuperblock) -> Result<u32> {
        if self.count >= MAX_NFS_MOUNTS {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_id;
        self.next_id += 1;
        sb.mount_id = id;
        for slot in &mut self.mounts {
            if slot.is_none() {
                *slot = Some(sb);
                self.count += 1;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Removes a mount by ID.
    fn remove(&mut self, id: u32) -> Option<NfsSuperblock> {
        for slot in &mut self.mounts {
            if slot.as_ref().map(|m| m.mount_id) == Some(id) {
                self.count -= 1;
                return slot.take();
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Mount / unmount operations
// ---------------------------------------------------------------------------

/// Performs an NFS mount operation.
///
/// Creates a new superblock, negotiates with the server (placeholder RPC),
/// retrieves the root file handle, and registers with the mount table.
///
/// Returns the mount ID on success.
pub fn mount_nfs(table: &mut NfsMountTable, info: NfsMountInfo) -> Result<u32> {
    info.validate()?;

    let id = table.next_id;
    let mut sb = NfsSuperblock::new(info, id);

    // Simulate root file handle retrieval (placeholder).
    // In a real implementation this would perform an RPC MOUNT call.
    let mut fh = NfsFileHandle::new();
    let synthetic_fh = [0x00u8, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
    fh.set(&synthetic_fh)?;
    sb.root_fh = fh;
    sb.mounted = true;
    sb.rpc_calls += 1;

    table.insert(sb)
}

/// Performs an NFS unmount operation.
///
/// Flushes dirty pages, sends an RPC UMNT call (placeholder), and
/// removes the superblock from the mount table.
pub fn nfs_umount(table: &mut NfsMountTable, mount_id: u32) -> Result<()> {
    let sb = table.get_mut(mount_id).ok_or(Error::NotFound)?;

    if !sb.mounted {
        return Err(Error::InvalidArgument);
    }

    // Flush dirty pages (placeholder).
    if sb.dirty {
        // In a real implementation: flush writeback cache.
        sb.dirty = false;
        sb.rpc_calls += 1;
    }

    // Mark as unmounted.
    sb.mounted = false;

    // Remove from table.
    table.remove(mount_id).ok_or(Error::NotFound)?;
    Ok(())
}
