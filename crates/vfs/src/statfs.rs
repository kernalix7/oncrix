// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Filesystem statistics (statfs/fstatfs).
//!
//! Provides POSIX-compatible filesystem statistics including
//! block counts, inode counts, and mount flags. Supports
//! registering multiple mounted filesystems and querying
//! statistics by path or mount identifier.

use oncrix_lib::{Error, Result};

// ── Filesystem type magic numbers ──────────────────────────────

/// EXT2/EXT3/EXT4 filesystem magic number.
pub const EXT2_MAGIC: u64 = 0xEF53;

/// tmpfs filesystem magic number.
pub const TMPFS_MAGIC: u64 = 0x0102_1994;

/// ramfs filesystem magic number.
pub const RAMFS_MAGIC: u64 = 0x8584_58f6;

/// procfs filesystem magic number.
pub const PROCFS_MAGIC: u64 = 0x9fa0;

/// sysfs filesystem magic number.
pub const SYSFS_MAGIC: u64 = 0x6265_6572;

/// devfs filesystem magic number.
pub const DEVFS_MAGIC: u64 = 0x1373;

/// FAT32 (MSDOS) filesystem magic number.
pub const FAT32_MAGIC: u64 = 0x4d44;

/// OverlayFS filesystem magic number.
pub const OVERLAYFS_MAGIC: u64 = 0x794c_7630;

/// pipefs filesystem magic number.
pub const PIPEFS_MAGIC: u64 = 0x5049_5045;

// ── Mount flags ────────────────────────────────────────────────

/// Mount is read-only.
pub const ST_RDONLY: u64 = 1;

/// Disallow set-user-ID / set-group-ID bits.
pub const ST_NOSUID: u64 = 2;

/// Disallow access to device special files.
pub const ST_NODEV: u64 = 4;

/// Disallow program execution.
pub const ST_NOEXEC: u64 = 8;

/// Do not update access times.
pub const ST_NOATIME: u64 = 1024;

/// Update atime relative to mtime/ctime.
pub const ST_RELATIME: u64 = 4096;

// ── Statfs ─────────────────────────────────────────────────────

/// Maximum number of registered mount entries.
const MAX_ENTRIES: usize = 32;

/// Maximum path length for a mount point.
const MAX_PATH: usize = 64;

/// Filesystem statistics structure (POSIX `struct statfs`).
///
/// All fields follow the standard POSIX/Linux `statfs` layout
/// and use 64-bit widths for large-volume support.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Statfs {
    /// Type of filesystem (magic number).
    pub f_type: u64,
    /// Optimal transfer block size.
    pub f_bsize: u64,
    /// Total data blocks in filesystem.
    pub f_blocks: u64,
    /// Free blocks in filesystem.
    pub f_bfree: u64,
    /// Free blocks available to unprivileged users.
    pub f_bavail: u64,
    /// Total inodes in filesystem.
    pub f_files: u64,
    /// Free inodes in filesystem.
    pub f_ffree: u64,
    /// Filesystem ID.
    pub f_fsid: [u32; 2],
    /// Maximum length of filenames.
    pub f_namelen: u64,
    /// Fragment size (since Linux 2.6).
    pub f_frsize: u64,
    /// Mount flags (ST_RDONLY, ST_NOSUID, etc.).
    pub f_flags: u64,
}

impl Statfs {
    /// Returns the percentage of blocks in use (0–100).
    ///
    /// Returns 0 when the filesystem has no blocks.
    pub fn usage_percent(&self) -> u64 {
        if self.f_blocks == 0 {
            return 0;
        }
        let used = self.f_blocks.saturating_sub(self.f_bfree);
        used * 100 / self.f_blocks
    }
}

/// Convenience builder for [`Statfs`].
///
/// Creates a `Statfs` with the most commonly needed fields
/// filled in, leaving the rest at their defaults.
pub fn make_statfs(
    fs_type: u64,
    bsize: u64,
    blocks: u64,
    bfree: u64,
    files: u64,
    ffree: u64,
    namelen: u64,
) -> Statfs {
    Statfs {
        f_type: fs_type,
        f_bsize: bsize,
        f_blocks: blocks,
        f_bfree: bfree,
        f_bavail: bfree,
        f_files: files,
        f_ffree: ffree,
        f_namelen: namelen,
        f_frsize: bsize,
        ..Statfs::default()
    }
}

// ── FsStatProvider ─────────────────────────────────────────────

/// Internal mount-point entry for [`FsStatProvider`].
#[derive(Clone, Copy)]
struct MountEntry {
    /// Unique mount identifier.
    mount_id: u32,
    /// Filesystem type magic number.
    fs_type: u64,
    /// Cached filesystem statistics.
    statfs: Statfs,
    /// Mount-point path bytes.
    path: [u8; MAX_PATH],
    /// Valid length of `path`.
    path_len: usize,
    /// Whether this slot is occupied.
    active: bool,
}

impl Default for MountEntry {
    fn default() -> Self {
        Self {
            mount_id: 0,
            fs_type: 0,
            statfs: Statfs::default(),
            path: [0u8; MAX_PATH],
            path_len: 0,
            active: false,
        }
    }
}

/// Provider of filesystem statistics for registered mounts.
///
/// Maintains up to 32 mount-point entries. Each entry records
/// the mount path, filesystem type, and current [`Statfs`].
pub struct FsStatProvider {
    /// Registered mount entries.
    entries: [MountEntry; MAX_ENTRIES],
    /// Number of active entries.
    count: usize,
}

impl Default for FsStatProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl FsStatProvider {
    /// Creates a new, empty provider.
    pub const fn new() -> Self {
        const EMPTY: MountEntry = MountEntry {
            mount_id: 0,
            fs_type: 0,
            statfs: Statfs {
                f_type: 0,
                f_bsize: 0,
                f_blocks: 0,
                f_bfree: 0,
                f_bavail: 0,
                f_files: 0,
                f_ffree: 0,
                f_fsid: [0; 2],
                f_namelen: 0,
                f_frsize: 0,
                f_flags: 0,
            },
            path: [0u8; MAX_PATH],
            path_len: 0,
            active: false,
        };
        Self {
            entries: [EMPTY; MAX_ENTRIES],
            count: 0,
        }
    }

    /// Registers a mounted filesystem.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full,
    /// [`Error::AlreadyExists`] if `mount_id` is already
    /// registered, or [`Error::InvalidArgument`] if `path`
    /// exceeds 64 bytes.
    pub fn register_mount(
        &mut self,
        mount_id: u32,
        fs_type: u64,
        path: &[u8],
        statfs: Statfs,
    ) -> Result<()> {
        if path.len() > MAX_PATH {
            return Err(Error::InvalidArgument);
        }
        // Check for duplicate mount_id.
        let mut i = 0;
        while i < MAX_ENTRIES {
            if self.entries[i].active && self.entries[i].mount_id == mount_id {
                return Err(Error::AlreadyExists);
            }
            i += 1;
        }
        // Find a free slot.
        let mut i = 0;
        while i < MAX_ENTRIES {
            if !self.entries[i].active {
                let entry = &mut self.entries[i];
                entry.mount_id = mount_id;
                entry.fs_type = fs_type;
                entry.statfs = statfs;
                entry.path_len = path.len();
                let mut j = 0;
                while j < path.len() {
                    entry.path[j] = path[j];
                    j += 1;
                }
                entry.active = true;
                self.count += 1;
                return Ok(());
            }
            i += 1;
        }
        Err(Error::OutOfMemory)
    }

    /// Removes a registered mount by its identifier.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no mount with the given
    /// `mount_id` exists.
    pub fn unregister_mount(&mut self, mount_id: u32) -> Result<()> {
        let mut i = 0;
        while i < MAX_ENTRIES {
            if self.entries[i].active && self.entries[i].mount_id == mount_id {
                self.entries[i].active = false;
                self.count -= 1;
                return Ok(());
            }
            i += 1;
        }
        Err(Error::NotFound)
    }

    /// Updates the cached statistics for a mounted filesystem.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no mount with the given
    /// `mount_id` exists.
    pub fn update_stats(&mut self, mount_id: u32, statfs: Statfs) -> Result<()> {
        let mut i = 0;
        while i < MAX_ENTRIES {
            if self.entries[i].active && self.entries[i].mount_id == mount_id {
                self.entries[i].statfs = statfs;
                return Ok(());
            }
            i += 1;
        }
        Err(Error::NotFound)
    }

    /// Returns filesystem statistics for the given path.
    ///
    /// Performs a longest-prefix match against registered mount
    /// points to find the most specific mount.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching mount exists.
    pub fn do_statfs(&self, path: &[u8]) -> Result<Statfs> {
        let mut best_len: usize = 0;
        let mut best_idx: Option<usize> = None;

        let mut i = 0;
        while i < MAX_ENTRIES {
            if self.entries[i].active {
                let plen = self.entries[i].path_len;
                if path.len() >= plen
                    && Self::prefix_eq(&self.entries[i].path, plen, path)
                    && plen >= best_len
                {
                    best_len = plen;
                    best_idx = Some(i);
                }
            }
            i += 1;
        }
        match best_idx {
            Some(idx) => Ok(self.entries[idx].statfs),
            None => Err(Error::NotFound),
        }
    }

    /// Returns filesystem statistics for a mount identifier.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no mount with the given
    /// `mount_id` exists.
    pub fn do_fstatfs(&self, mount_id: u32) -> Result<Statfs> {
        let mut i = 0;
        while i < MAX_ENTRIES {
            if self.entries[i].active && self.entries[i].mount_id == mount_id {
                return Ok(self.entries[i].statfs);
            }
            i += 1;
        }
        Err(Error::NotFound)
    }

    /// Returns the number of active mount entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no mounts are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Compares the first `len` bytes of `stored` against the
    /// beginning of `input`.
    fn prefix_eq(stored: &[u8; MAX_PATH], len: usize, input: &[u8]) -> bool {
        let mut i = 0;
        while i < len {
            if stored[i] != input[i] {
                return false;
            }
            i += 1;
        }
        true
    }
}
