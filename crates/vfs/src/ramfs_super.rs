// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ramfs superblock operations.
//!
//! Implements the superblock layer for ramfs — a simple in-memory filesystem
//! with no size limit beyond available memory. ramfs is the canonical minimal
//! Linux-compatible VFS implementation: no backing store, no writeback, no
//! page reclaim.
//!
//! # Design
//!
//! - [`RamfsSuperblock`] — superblock with inode counter and optional size cap
//! - `ramfs_fill_super` — initialise a superblock for a new mount
//! - `ramfs_statfs` — report filesystem statistics
//! - `ramfs_mount` — entry point to mount a ramfs instance
//!
//! # References
//!
//! - Linux `mm/shmem.c`, `fs/ramfs/inode.c`
//! - man 8 mount (ramfs section)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of simultaneously mounted ramfs instances.
const MAX_RAMFS_MOUNTS: usize = 8;

/// Block size reported by statfs (4 KiB).
pub const RAMFS_BLOCK_SIZE: u64 = 4096;

/// ramfs filesystem magic (matches Linux `RAMFS_MAGIC = 0x858458F6`).
pub const RAMFS_MAGIC: u64 = 0x858458F6;

/// Default inode number for the ramfs root directory.
pub const RAMFS_ROOT_INO: u64 = 1;

// ---------------------------------------------------------------------------
// RamfsSuperblock
// ---------------------------------------------------------------------------

/// Superblock state for a mounted ramfs instance.
pub struct RamfsSuperblock {
    /// Filesystem magic (always `RAMFS_MAGIC`).
    pub magic: u64,
    /// Monotonically increasing inode counter.
    next_ino: u64,
    /// Current number of allocated inodes.
    pub inode_count: u64,
    /// Optional maximum number of inodes (0 = unlimited).
    pub max_inodes: u64,
    /// Total bytes currently in use by file data.
    pub bytes_used: u64,
    /// Optional maximum bytes (0 = unlimited).
    pub max_bytes: u64,
    /// Whether this superblock slot is in use.
    pub active: bool,
    /// Mount ID (index in the global mount table).
    pub mount_id: u32,
}

impl RamfsSuperblock {
    /// Create a blank superblock (not yet filled).
    pub const fn blank() -> Self {
        Self {
            magic: RAMFS_MAGIC,
            next_ino: RAMFS_ROOT_INO,
            inode_count: 0,
            max_inodes: 0,
            bytes_used: 0,
            max_bytes: 0,
            active: false,
            mount_id: 0,
        }
    }

    /// Allocate a new inode number.
    ///
    /// Returns `Err(OutOfMemory)` if `max_inodes` is set and would be exceeded.
    pub fn alloc_ino(&mut self) -> Result<u64> {
        if self.max_inodes > 0 && self.inode_count >= self.max_inodes {
            return Err(Error::OutOfMemory);
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.inode_count += 1;
        Ok(ino)
    }

    /// Release an inode (decrements the inode counter).
    pub fn free_ino(&mut self) {
        self.inode_count = self.inode_count.saturating_sub(1);
    }

    /// Allocate `bytes` from the in-use byte pool.
    ///
    /// Returns `Err(OutOfMemory)` if `max_bytes` is set and would be exceeded.
    pub fn alloc_bytes(&mut self, bytes: u64) -> Result<()> {
        if self.max_bytes > 0 && self.bytes_used.saturating_add(bytes) > self.max_bytes {
            return Err(Error::OutOfMemory);
        }
        self.bytes_used = self.bytes_used.saturating_add(bytes);
        Ok(())
    }

    /// Release `bytes` from the in-use byte pool.
    pub fn free_bytes(&mut self, bytes: u64) {
        self.bytes_used = self.bytes_used.saturating_sub(bytes);
    }

    /// Return the number of free bytes (0 if no limit is set).
    pub fn free_bytes_count(&self) -> u64 {
        if self.max_bytes == 0 {
            u64::MAX
        } else {
            self.max_bytes.saturating_sub(self.bytes_used)
        }
    }

    /// Return the number of free inodes (u64::MAX if no limit is set).
    pub fn free_ino_count(&self) -> u64 {
        if self.max_inodes == 0 {
            u64::MAX
        } else {
            self.max_inodes.saturating_sub(self.inode_count)
        }
    }
}

// ---------------------------------------------------------------------------
// RamfsStatfs
// ---------------------------------------------------------------------------

/// POSIX statfs information for a ramfs mount.
#[derive(Clone, Copy, Debug, Default)]
pub struct RamfsStatfs {
    /// Filesystem type magic.
    pub f_type: u64,
    /// Block size.
    pub f_bsize: u64,
    /// Total blocks (0 = dynamic, reported as very large).
    pub f_blocks: u64,
    /// Free blocks.
    pub f_bfree: u64,
    /// Available blocks (same as free for ramfs).
    pub f_bavail: u64,
    /// Total inodes.
    pub f_files: u64,
    /// Free inodes.
    pub f_ffree: u64,
    /// Filesystem name size limit.
    pub f_namelen: u64,
}

// ---------------------------------------------------------------------------
// Mount table
// ---------------------------------------------------------------------------

/// Global table of mounted ramfs instances.
pub struct RamfsMountTable {
    mounts: [RamfsSuperblock; MAX_RAMFS_MOUNTS],
}

impl RamfsMountTable {
    /// Create an empty mount table.
    pub const fn new() -> Self {
        Self {
            mounts: [const { RamfsSuperblock::blank() }; MAX_RAMFS_MOUNTS],
        }
    }

    /// Fill a new superblock and return its mount ID.
    ///
    /// `max_inodes` and `max_bytes` may be 0 for no limit.
    ///
    /// Returns `Err(OutOfMemory)` if all slots are taken.
    pub fn ramfs_fill_super(&mut self, max_inodes: u64, max_bytes: u64) -> Result<u32> {
        let slot = self
            .mounts
            .iter()
            .position(|m| !m.active)
            .ok_or(Error::OutOfMemory)?;
        let sb = &mut self.mounts[slot];
        sb.magic = RAMFS_MAGIC;
        sb.next_ino = RAMFS_ROOT_INO;
        sb.inode_count = 0;
        sb.max_inodes = max_inodes;
        sb.bytes_used = 0;
        sb.max_bytes = max_bytes;
        sb.mount_id = slot as u32;
        sb.active = true;
        Ok(slot as u32)
    }

    /// Return statfs information for the mount with `mount_id`.
    ///
    /// Returns `Err(NotFound)` if no such mount exists.
    pub fn ramfs_statfs(&self, mount_id: u32) -> Result<RamfsStatfs> {
        let sb = self.get(mount_id)?;
        let blocks_used = sb.bytes_used.div_ceil(RAMFS_BLOCK_SIZE);
        let total_blocks = if sb.max_bytes > 0 {
            sb.max_bytes / RAMFS_BLOCK_SIZE
        } else {
            u64::MAX / 2 // Report a very large number for unlimited ramfs.
        };
        let free_blocks = total_blocks.saturating_sub(blocks_used);

        Ok(RamfsStatfs {
            f_type: RAMFS_MAGIC,
            f_bsize: RAMFS_BLOCK_SIZE,
            f_blocks: total_blocks,
            f_bfree: free_blocks,
            f_bavail: free_blocks,
            f_files: if sb.max_inodes > 0 {
                sb.max_inodes
            } else {
                u64::MAX / 2
            },
            f_ffree: sb.free_ino_count(),
            f_namelen: 255,
        })
    }

    /// Mount a new ramfs instance (alias for `ramfs_fill_super`).
    ///
    /// This is the entry point called by the VFS `mount` syscall.
    pub fn ramfs_mount(&mut self, max_inodes: u64, max_bytes: u64) -> Result<u32> {
        self.ramfs_fill_super(max_inodes, max_bytes)
    }

    /// Unmount the ramfs instance with `mount_id`.
    ///
    /// Returns `Err(NotFound)` if no such mount exists.
    /// Returns `Err(Busy)` if inodes are still in use.
    pub fn ramfs_unmount(&mut self, mount_id: u32) -> Result<()> {
        let sb = self.get_mut(mount_id)?;
        if sb.inode_count > 0 {
            return Err(Error::Busy);
        }
        *sb = RamfsSuperblock::blank();
        Ok(())
    }

    /// Return a reference to the superblock for `mount_id`.
    pub fn get(&self, mount_id: u32) -> Result<&RamfsSuperblock> {
        let idx = mount_id as usize;
        if idx >= MAX_RAMFS_MOUNTS || !self.mounts[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&self.mounts[idx])
    }

    /// Return a mutable reference to the superblock for `mount_id`.
    pub fn get_mut(&mut self, mount_id: u32) -> Result<&mut RamfsSuperblock> {
        let idx = mount_id as usize;
        if idx >= MAX_RAMFS_MOUNTS || !self.mounts[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&mut self.mounts[idx])
    }

    /// Return the number of active mounts.
    pub fn mount_count(&self) -> usize {
        self.mounts.iter().filter(|m| m.active).count()
    }
}
