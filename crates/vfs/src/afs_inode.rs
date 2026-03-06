// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AFS (Andrew File System) in-memory inode (vnode) representation.
//!
//! In AFS, server-side file objects are called "vnodes". This module
//! implements the client-side in-memory inode that caches AFS vnode
//! metadata and tracks cache coherency state.
//!
//! # Cache Status
//!
//! Each AFS inode tracks whether its metadata and data caches are valid.
//! Validity is determined by the callback promise received from the server
//! (see `afs_callback.rs`). When the callback breaks, the inode is
//! invalidated and must be refetched.
//!
//! # Fetch Status
//!
//! `AFSFetchStatus` contains the full vnode metadata returned by the server
//! in `FetchStatus` RPCs. It is equivalent to a POSIX stat structure plus
//! AFS-specific fields.

use oncrix_lib::{Error, Result};

/// AFS file types in the vnode's type field.
pub mod vnode_type {
    /// Regular file.
    pub const FILE: u32 = 1;
    /// Directory.
    pub const DIRECTORY: u32 = 2;
    /// Symbolic link.
    pub const SYMLINK: u32 = 3;
    /// Mount point (to another volume).
    pub const MOUNT_POINT: u32 = 4;
}

/// AFS `AFSFetchStatus` (vnode metadata from the fileserver).
#[derive(Clone, Copy, Default)]
pub struct AfsFetchStatus {
    /// File type (see [`vnode_type`]).
    pub file_type: u32,
    /// Number of hard links.
    pub nlink: u32,
    /// File size in bytes.
    pub size: u64,
    /// Version number (incremented on every modification).
    pub data_version: u64,
    /// Author UID.
    pub author: u32,
    /// Owner UID.
    pub owner: u32,
    /// Group ID.
    pub group: u32,
    /// POSIX mode bits (low 12 bits).
    pub mode: u32,
    /// Client modification time (Unix timestamp).
    pub client_mtime: u32,
    /// Server modification time (Unix timestamp).
    pub server_mtime: u32,
    /// Number of 1-KiB blocks used.
    pub blocks_used: u32,
    /// Abort code (0 if successful).
    pub abort_code: u32,
}

impl AfsFetchStatus {
    /// Parses `AFSFetchStatus` from 21 XDR u32 values (84 bytes, big-endian).
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 84 {
            return Err(Error::InvalidArgument);
        }
        let read_u32 =
            |off: usize| u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]);
        let read_u64 = |off: usize| {
            let hi = read_u32(off) as u64;
            let lo = read_u32(off + 4) as u64;
            (hi << 32) | lo
        };
        Ok(Self {
            file_type: read_u32(0),
            nlink: read_u32(4),
            size: read_u64(8),
            data_version: read_u64(16),
            author: read_u32(24),
            owner: read_u32(28),
            group: read_u32(32),
            mode: read_u32(36) & 0xFFF,
            client_mtime: read_u32(40),
            server_mtime: read_u32(44),
            blocks_used: read_u32(48),
            abort_code: read_u32(52),
        })
    }

    /// Returns `true` if this vnode is a directory.
    pub const fn is_dir(&self) -> bool {
        self.file_type == vnode_type::DIRECTORY
    }

    /// Returns `true` if this vnode is a regular file.
    pub const fn is_regular(&self) -> bool {
        self.file_type == vnode_type::FILE
    }

    /// Returns `true` if this vnode is a symbolic link.
    pub const fn is_symlink(&self) -> bool {
        self.file_type == vnode_type::SYMLINK
    }
}

/// Cache validity flags for an AFS inode.
#[derive(Clone, Copy, Default)]
pub struct AfsInodeCacheFlags {
    /// Metadata (stat) is valid.
    pub stat_valid: bool,
    /// Directory content is valid.
    pub dir_valid: bool,
    /// File data pages are valid.
    pub data_valid: bool,
}

/// An AFS in-memory inode (client-side vnode cache entry).
#[derive(Clone, Copy, Default)]
pub struct AfsInode {
    /// Volume ID.
    pub volume_id: u32,
    /// Vnode number.
    pub vnode: u32,
    /// Vnode uniquifier.
    pub unique: u32,
    /// Cached fetch status.
    pub status: AfsFetchStatus,
    /// Cache validity flags.
    pub cache: AfsInodeCacheFlags,
    /// Data version when the cache was last populated.
    pub cached_data_version: u64,
    /// Whether there are pending writes not yet sent to the server.
    pub dirty: bool,
    /// Number of open file descriptors on this inode.
    pub open_count: u32,
}

impl AfsInode {
    /// Creates a new AFS inode with the given FID components and fetched status.
    pub fn new(volume_id: u32, vnode: u32, unique: u32, status: AfsFetchStatus) -> Self {
        Self {
            volume_id,
            vnode,
            unique,
            cached_data_version: status.data_version,
            status,
            cache: AfsInodeCacheFlags {
                stat_valid: true,
                dir_valid: false,
                data_valid: false,
            },
            dirty: false,
            open_count: 0,
        }
    }

    /// Invalidates all cached data for this inode.
    pub fn invalidate(&mut self) {
        self.cache.stat_valid = false;
        self.cache.dir_valid = false;
        self.cache.data_valid = false;
    }

    /// Updates the cached status with a new `AFSFetchStatus`.
    ///
    /// Returns `true` if the data version changed (data cache must also be invalidated).
    pub fn update_status(&mut self, new_status: AfsFetchStatus) -> bool {
        let version_changed = new_status.data_version != self.cached_data_version;
        self.status = new_status;
        self.cache.stat_valid = true;
        if version_changed {
            self.cached_data_version = new_status.data_version;
            self.cache.data_valid = false;
        }
        version_changed
    }
}
