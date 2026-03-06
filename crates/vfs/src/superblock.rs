// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Filesystem superblock — per-mount metadata and operations.
//!
//! Each mounted filesystem has a superblock describing its properties
//! and linking to its root inode.

use crate::inode::InodeNumber;

/// Filesystem type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsType {
    /// In-memory RAM filesystem.
    Ramfs,
    /// Temporary filesystem (page-backed in-memory).
    Tmpfs,
    /// ext2 filesystem (read-only).
    Ext2,
    /// Device-backed filesystem (future).
    DevFs,
    /// Proc filesystem (future).
    ProcFs,
}

impl core::fmt::Display for FsType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Ramfs => write!(f, "ramfs"),
            Self::Tmpfs => write!(f, "tmpfs"),
            Self::Ext2 => write!(f, "ext2"),
            Self::DevFs => write!(f, "devfs"),
            Self::ProcFs => write!(f, "procfs"),
        }
    }
}

/// Superblock — per-mount filesystem instance.
#[derive(Debug)]
pub struct Superblock {
    /// Filesystem type.
    pub fs_type: FsType,
    /// Root inode number.
    pub root: InodeNumber,
    /// Block size (bytes). 0 for pseudo-filesystems.
    pub block_size: u32,
    /// Maximum filename length.
    pub max_name_len: u32,
    /// Read-only flag.
    pub read_only: bool,
}

impl Superblock {
    /// Create a new superblock.
    pub const fn new(fs_type: FsType, root: InodeNumber) -> Self {
        Self {
            fs_type,
            root,
            block_size: 0,
            max_name_len: 255,
            read_only: false,
        }
    }
}

/// Maximum number of mount points.
const MAX_MOUNTS: usize = 16;

/// Global mount table.
///
/// Maps mount-point paths to superblocks. A production kernel
/// would use a proper VFS mount tree; this fixed-size table
/// suffices for early boot.
pub struct MountTable {
    /// Mounted filesystems.
    mounts: [Option<MountEntry>; MAX_MOUNTS],
    /// Number of active mounts.
    count: usize,
}

impl core::fmt::Debug for MountTable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MountTable")
            .field("count", &self.count)
            .finish()
    }
}

/// A single mount point entry.
#[derive(Debug)]
pub struct MountEntry {
    /// Mount point path (e.g., "/" or "/dev").
    path: MountPath,
    /// Associated superblock.
    pub superblock: Superblock,
}

/// Fixed-size mount path buffer.
#[derive(Debug)]
pub struct MountPath {
    /// Path bytes.
    buf: [u8; 256],
    /// Path length.
    len: usize,
}

impl MountPath {
    /// Create a mount path from a string slice.
    pub fn from_path(s: &str) -> Option<Self> {
        let bytes = s.as_bytes();
        if bytes.is_empty() || bytes.len() > 256 {
            return None;
        }
        let mut buf = [0u8; 256];
        buf[..bytes.len()].copy_from_slice(bytes);
        Some(Self {
            buf,
            len: bytes.len(),
        })
    }

    /// Return the path as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl Default for MountTable {
    fn default() -> Self {
        Self::new()
    }
}

impl MountTable {
    /// Create an empty mount table.
    pub const fn new() -> Self {
        const NONE: Option<MountEntry> = None;
        Self {
            mounts: [NONE; MAX_MOUNTS],
            count: 0,
        }
    }

    /// Mount a filesystem at the given path.
    pub fn mount(&mut self, path: &str, superblock: Superblock) -> oncrix_lib::Result<()> {
        if self.count >= MAX_MOUNTS {
            return Err(oncrix_lib::Error::OutOfMemory);
        }
        let mount_path = MountPath::from_path(path).ok_or(oncrix_lib::Error::InvalidArgument)?;

        for slot in self.mounts.iter_mut() {
            if slot.is_none() {
                *slot = Some(MountEntry {
                    path: mount_path,
                    superblock,
                });
                self.count += 1;
                return Ok(());
            }
        }
        Err(oncrix_lib::Error::OutOfMemory)
    }

    /// Look up a mount entry by path.
    pub fn find(&self, path: &str) -> Option<&MountEntry> {
        let path_bytes = path.as_bytes();
        self.mounts
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|m| m.path.as_bytes() == path_bytes)
    }

    /// Return the number of active mounts.
    pub fn count(&self) -> usize {
        self.count
    }
}
