// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! XFS symbolic link implementation.
//!
//! XFS stores short symlink targets inline in the inode (< 512 bytes by
//! default) and longer targets in a dedicated remote symlink block.  This
//! module implements both storage paths, the on-disk remote-symlink block
//! format, and the read-side logic used during path resolution.

use oncrix_lib::{Error, Result};

/// Maximum length of an XFS symbolic link target (POSIX PATH_MAX - 1).
pub const XFS_SYMLINK_MAXLEN: usize = 1023;

/// Threshold at which a symlink is stored in the inode vs. a remote block.
pub const XFS_INLINE_SYMLINK_THRESHOLD: usize = 256;

/// Magic number in a remote symlink block header.
pub const XFS_SYMLINK_MAGIC: u32 = 0x58534c4d; // "XSLM"

/// XFS remote symlink block header.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct XfsSymlinkHdr {
    /// Magic number.
    pub magic: u32,
    /// CRC32c of the block (0 if not using v5 metadata).
    pub crc: u32,
    /// Logical block offset within the symlink data (always 0 for short links).
    pub offset: u32,
    /// Number of bytes in this block.
    pub bytes: u32,
    /// File system UUID (16 bytes).
    pub uuid: [u8; 16],
    /// Owning inode number.
    pub owner: u64,
    /// Block number of this remote block.
    pub blkno: u64,
    pub _pad: u32,
}

impl XfsSymlinkHdr {
    /// Validate the magic field.
    pub fn is_valid(&self) -> bool {
        self.magic == XFS_SYMLINK_MAGIC
    }
}

/// An XFS symlink — either inline or remote.
#[derive(Debug, Clone)]
pub enum XfsSymlinkData {
    /// Target fits inside the inode's literal area.
    Inline {
        target: [u8; XFS_INLINE_SYMLINK_THRESHOLD],
        len: u16,
    },
    /// Target is stored in one or more remote blocks.
    Remote {
        /// Logical file system block where the remote data starts.
        first_block: u64,
        /// Total byte length of the target.
        len: u16,
        /// Number of remote blocks used.
        block_count: u32,
    },
}

impl XfsSymlinkData {
    /// Create an inline symlink target.
    pub fn new_inline(target: &[u8]) -> Result<Self> {
        if target.len() > XFS_INLINE_SYMLINK_THRESHOLD {
            return Err(Error::InvalidArgument);
        }
        if target.len() > XFS_SYMLINK_MAXLEN {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; XFS_INLINE_SYMLINK_THRESHOLD];
        buf[..target.len()].copy_from_slice(target);
        Ok(Self::Inline {
            target: buf,
            len: target.len() as u16,
        })
    }

    /// Create a remote symlink descriptor.
    pub fn new_remote(first_block: u64, len: u16, block_count: u32) -> Result<Self> {
        if len as usize > XFS_SYMLINK_MAXLEN {
            return Err(Error::InvalidArgument);
        }
        Ok(Self::Remote {
            first_block,
            len,
            block_count,
        })
    }

    /// Target length in bytes.
    pub fn len(&self) -> usize {
        match self {
            Self::Inline { len, .. } => *len as usize,
            Self::Remote { len, .. } => *len as usize,
        }
    }

    /// Whether the symlink target is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether the target is stored inline.
    pub fn is_inline(&self) -> bool {
        matches!(self, Self::Inline { .. })
    }

    /// Read bytes of an inline symlink target into `out`.
    ///
    /// Returns `Err(IoError)` for remote symlinks (caller must read blocks).
    pub fn read_inline(&self, off: usize, out: &mut [u8]) -> Result<usize> {
        match self {
            Self::Inline { target, len } => {
                let total = *len as usize;
                if off >= total {
                    return Ok(0);
                }
                let to_copy = (total - off).min(out.len());
                out[..to_copy].copy_from_slice(&target[off..off + to_copy]);
                Ok(to_copy)
            }
            Self::Remote { .. } => Err(Error::IoError),
        }
    }
}

/// Symlink cache entry for the VFS dentry cache.
#[derive(Debug, Clone)]
pub struct XfsSymlinkCache {
    /// Inode number of the symlink.
    pub ino: u64,
    /// Generation number (for stale cache detection).
    pub generation: u32,
    /// Cached target bytes.
    target: [u8; XFS_SYMLINK_MAXLEN + 1],
    target_len: u16,
}

impl XfsSymlinkCache {
    /// Create a new cache entry.
    pub fn new(ino: u64, generation: u32, target: &[u8]) -> Result<Self> {
        if target.len() > XFS_SYMLINK_MAXLEN {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; XFS_SYMLINK_MAXLEN + 1];
        buf[..target.len()].copy_from_slice(target);
        Ok(Self {
            ino,
            generation,
            target: buf,
            target_len: target.len() as u16,
        })
    }

    /// Return the cached target as a byte slice.
    pub fn target_bytes(&self) -> &[u8] {
        &self.target[..self.target_len as usize]
    }
}

/// Round up a symlink byte count to the XFS filesystem block size.
pub fn xfs_symlink_blocks(len: usize, block_size: usize) -> u32 {
    if len == 0 || block_size == 0 {
        return 0;
    }
    // Account for header.
    let data_per_block = block_size.saturating_sub(core::mem::size_of::<XfsSymlinkHdr>());
    if data_per_block == 0 {
        return 0;
    }
    ((len + data_per_block - 1) / data_per_block) as u32
}
