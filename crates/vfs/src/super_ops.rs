// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Superblock operations — mount, sync, umount lifecycle.
//!
//! Defines the `SuperOps` trait that every filesystem must implement and
//! provides the `SuperblockManager` registry for VFS-level mount/unmount.

use oncrix_lib::{Error, Result};

/// Maximum number of simultaneously registered filesystem types.
pub const MAX_FS_TYPES: usize = 32;

/// Maximum number of concurrently mounted filesystems.
pub const MAX_MOUNTS: usize = 64;

/// Flags passed to `mount()`.
#[derive(Debug, Clone, Copy, Default)]
pub struct MountFlags(pub u32);

impl MountFlags {
    /// Mount read-only.
    pub const RDONLY: u32 = 1 << 0;
    /// Do not allow set-uid programs.
    pub const NOSUID: u32 = 1 << 1;
    /// Do not allow device file access.
    pub const NODEV: u32 = 1 << 2;
    /// Do not allow program execution.
    pub const NOEXEC: u32 = 1 << 3;
    /// Synchronous I/O.
    pub const SYNCHRONOUS: u32 = 1 << 4;
    /// Remount existing mount.
    pub const REMOUNT: u32 = 1 << 5;
    /// Do not update access times.
    pub const NOATIME: u32 = 1 << 10;

    /// Test whether a flag is set.
    pub const fn has(self, flag: u32) -> bool {
        (self.0 & flag) != 0
    }
}

/// Filesystem-level statistics returned by `statfs`.
#[derive(Debug, Clone, Copy, Default)]
pub struct FsStats {
    /// Filesystem type magic number.
    pub fs_type: u32,
    /// Block size in bytes.
    pub block_size: u32,
    /// Total data blocks in filesystem.
    pub blocks: u64,
    /// Free blocks available to superuser.
    pub blocks_free: u64,
    /// Free blocks available to unprivileged users.
    pub blocks_avail: u64,
    /// Total file nodes (inodes).
    pub files: u64,
    /// Free file nodes.
    pub files_free: u64,
    /// Maximum filename length.
    pub name_max: u32,
}

/// Superblock operations that every filesystem type must implement.
pub trait SuperOps {
    /// Allocate a new inode in this filesystem.
    ///
    /// Returns the new inode number on success.
    fn alloc_inode(&mut self, sb_id: u64) -> Result<u64>;

    /// Destroy (free) an inode number previously allocated.
    fn destroy_inode(&mut self, sb_id: u64, ino: u64) -> Result<()>;

    /// Write the superblock to persistent storage.
    fn write_super(&mut self, sb_id: u64) -> Result<()>;

    /// Synchronize dirty filesystem data and metadata.
    fn sync_fs(&mut self, sb_id: u64, wait: bool) -> Result<()>;

    /// Freeze I/O on the filesystem (for snapshot/backup).
    fn freeze_fs(&mut self, sb_id: u64) -> Result<()>;

    /// Unfreeze I/O on the filesystem.
    fn unfreeze_fs(&mut self, sb_id: u64) -> Result<()>;

    /// Return filesystem statistics.
    fn statfs(&self, sb_id: u64) -> Result<FsStats>;

    /// Remount the filesystem with new flags.
    fn remount_fs(&mut self, sb_id: u64, flags: MountFlags) -> Result<()>;

    /// Put (release) the superblock on the last close.
    fn put_super(&mut self, sb_id: u64);
}

/// A registered filesystem type entry.
#[derive(Clone, Copy)]
pub struct FsTypeEntry {
    /// Filesystem type name (e.g., "ext4", "tmpfs").
    pub name: &'static str,
    /// Magic number identifying the filesystem.
    pub magic: u32,
    /// Whether this FS requires a block device.
    pub requires_dev: bool,
}

impl FsTypeEntry {
    /// Create a new filesystem type entry.
    pub const fn new(name: &'static str, magic: u32, requires_dev: bool) -> Self {
        Self {
            name,
            magic,
            requires_dev,
        }
    }
}

/// A mounted filesystem record.
#[derive(Debug, Clone, Copy)]
pub struct MountRecord {
    /// Unique superblock identifier.
    pub sb_id: u64,
    /// Index of the filesystem type in the type registry.
    pub fs_type_idx: u8,
    /// Mount flags at time of mount.
    pub flags: MountFlags,
    /// Mount point inode number (in parent filesystem).
    pub mountpoint_ino: u64,
    /// Device number (0 for pseudo-filesystems).
    pub dev: u64,
    /// Whether this mount is currently frozen.
    pub frozen: bool,
}

impl MountRecord {
    const fn new_empty() -> Self {
        Self {
            sb_id: 0,
            fs_type_idx: 0,
            flags: MountFlags(0),
            mountpoint_ino: 0,
            dev: 0,
            frozen: false,
        }
    }
}

/// The VFS superblock/mount manager.
pub struct SuperblockManager {
    fs_types: [Option<FsTypeEntry>; MAX_FS_TYPES],
    mounts: [Option<MountRecord>; MAX_MOUNTS],
    next_sb_id: u64,
    mount_count: usize,
    fs_type_count: usize,
}

impl SuperblockManager {
    /// Create an empty superblock manager.
    pub const fn new() -> Self {
        Self {
            fs_types: [const { None }; MAX_FS_TYPES],
            mounts: [const { None }; MAX_MOUNTS],
            next_sb_id: 1,
            mount_count: 0,
            fs_type_count: 0,
        }
    }

    /// Register a new filesystem type.
    pub fn register_fs_type(&mut self, entry: FsTypeEntry) -> Result<usize> {
        if self.fs_type_count >= MAX_FS_TYPES {
            return Err(Error::OutOfMemory);
        }
        for slot in self.fs_types.iter_mut() {
            if slot.is_none() {
                *slot = Some(entry);
                self.fs_type_count += 1;
                return Ok(self.fs_type_count - 1);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregister a filesystem type by name.
    pub fn unregister_fs_type(&mut self, name: &str) -> Result<()> {
        for slot in self.fs_types.iter_mut() {
            if let Some(e) = slot {
                if e.name == name {
                    *slot = None;
                    self.fs_type_count -= 1;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Find a registered filesystem type by name.
    pub fn find_fs_type(&self, name: &str) -> Option<(usize, &FsTypeEntry)> {
        for (i, slot) in self.fs_types.iter().enumerate() {
            if let Some(e) = slot {
                if e.name == name {
                    return Some((i, e));
                }
            }
        }
        None
    }

    /// Record a new mount, allocating a superblock ID.
    ///
    /// Returns the new `sb_id` on success.
    pub fn do_mount(
        &mut self,
        fs_name: &str,
        flags: MountFlags,
        mountpoint_ino: u64,
        dev: u64,
    ) -> Result<u64> {
        if self.mount_count >= MAX_MOUNTS {
            return Err(Error::OutOfMemory);
        }
        let (fs_type_idx, _) = self.find_fs_type(fs_name).ok_or(Error::NotFound)?;
        let sb_id = self.next_sb_id;
        self.next_sb_id += 1;

        for slot in self.mounts.iter_mut() {
            if slot.is_none() {
                *slot = Some(MountRecord {
                    sb_id,
                    fs_type_idx: fs_type_idx as u8,
                    flags,
                    mountpoint_ino,
                    dev,
                    frozen: false,
                });
                self.mount_count += 1;
                return Ok(sb_id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a mount record (unmount).
    pub fn do_umount(&mut self, sb_id: u64) -> Result<()> {
        for slot in self.mounts.iter_mut() {
            if let Some(m) = slot {
                if m.sb_id == sb_id {
                    *slot = None;
                    self.mount_count -= 1;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Look up a mount record by superblock ID.
    pub fn get_mount(&self, sb_id: u64) -> Option<&MountRecord> {
        for slot in self.mounts.iter() {
            if let Some(m) = slot {
                if m.sb_id == sb_id {
                    return Some(m);
                }
            }
        }
        None
    }

    /// Return the number of currently active mounts.
    pub fn mount_count(&self) -> usize {
        self.mount_count
    }

    /// Iterate all active mounts, calling `f` for each.
    pub fn for_each_mount<F: FnMut(&MountRecord)>(&self, mut f: F) {
        for slot in self.mounts.iter() {
            if let Some(m) = slot {
                f(m);
            }
        }
    }

    /// Set freeze state for a mounted filesystem.
    pub fn set_frozen(&mut self, sb_id: u64, frozen: bool) -> Result<()> {
        for slot in self.mounts.iter_mut() {
            if let Some(m) = slot {
                if m.sb_id == sb_id {
                    m.frozen = frozen;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }
}

impl Default for SuperblockManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Check whether an operation is allowed given the mount flags.
///
/// Returns `Err(PermissionDenied)` if the mount is read-only and a write was
/// requested.
pub fn check_mount_writable(flags: MountFlags) -> Result<()> {
    if flags.has(MountFlags::RDONLY) {
        Err(Error::PermissionDenied)
    } else {
        Ok(())
    }
}
