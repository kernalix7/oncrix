// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `mount(2)` and `umount2(2)` syscall handlers.
//!
//! Attach or detach a filesystem to/from the directory tree.
//!
//! # POSIX Conformance
//!
//! `mount` is not in POSIX but is present on all UNIX systems.  Key behaviours:
//! - `EPERM` if the caller lacks `CAP_SYS_ADMIN`.
//! - `ENOENT` if the target mountpoint does not exist.
//! - `EBUSY` if a device is already mounted (without `MS_REMOUNT`).
//! - `MS_REMOUNT` remounts with new options without changing the filesystem.
//! - `MS_BIND` creates a bind mount.
//! - `MS_MOVE` moves a mount to a new location.
//! - `umount2(MNT_DETACH)` performs a lazy unmount.
//!
//! # References
//!
//! - Linux man pages: `mount(2)`, `umount(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Mount flags
// ---------------------------------------------------------------------------

/// Remount an existing mount.
pub const MS_REMOUNT: u64 = 32;
/// Create a bind mount.
pub const MS_BIND: u64 = 4096;
/// Move a mount to another location.
pub const MS_MOVE: u64 = 8192;
/// Mount read-only.
pub const MS_RDONLY: u64 = 1;
/// Ignore setuid/setgid bits.
pub const MS_NOSUID: u64 = 2;
/// Disallow device file access.
pub const MS_NODEV: u64 = 4;
/// Disallow program execution.
pub const MS_NOEXEC: u64 = 8;
/// Perform all I/O synchronously.
pub const MS_SYNCHRONOUS: u64 = 16;
/// Do not update access times.
pub const MS_NOATIME: u64 = 1024;

/// All known mount flag bits.
const MS_KNOWN: u64 = MS_REMOUNT
    | MS_BIND
    | MS_MOVE
    | MS_RDONLY
    | MS_NOSUID
    | MS_NODEV
    | MS_NOEXEC
    | MS_SYNCHRONOUS
    | MS_NOATIME;

// ---------------------------------------------------------------------------
// Umount flags
// ---------------------------------------------------------------------------

/// Force unmount even if busy.
pub const MNT_FORCE: i32 = 1;
/// Lazy unmount: detach but keep existing references alive.
pub const MNT_DETACH: i32 = 2;
/// Mark mount point as expired.
pub const MNT_EXPIRE: i32 = 4;

const MNT_KNOWN: i32 = MNT_FORCE | MNT_DETACH | MNT_EXPIRE;

// ---------------------------------------------------------------------------
// Mount record
// ---------------------------------------------------------------------------

/// A mounted filesystem entry.
#[derive(Debug, Clone, Copy)]
pub struct MountEntry {
    /// Source device or filesystem path.
    pub source: [u8; 256],
    /// Mountpoint path.
    pub target: [u8; 256],
    /// Filesystem type.
    pub fstype: [u8; 32],
    /// Mount flags.
    pub flags: u64,
    /// Whether this is a bind mount.
    pub is_bind: bool,
}

/// Maximum number of mounted filesystems.
pub const MAX_MOUNTS: usize = 64;

/// Mount table.
pub struct MountTable {
    entries: [Option<MountEntry>; MAX_MOUNTS],
    count: usize,
}

impl Default for MountTable {
    fn default() -> Self {
        Self::new()
    }
}

impl MountTable {
    /// Create an empty mount table.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; MAX_MOUNTS],
            count: 0,
        }
    }

    fn find_by_target(&self, target: &[u8]) -> Option<usize> {
        self.entries.iter().position(|e| {
            e.as_ref().map_or(false, |m| {
                let tlen = target.len().min(256);
                m.target[..tlen] == target[..tlen]
            })
        })
    }

    fn alloc_slot(&self) -> Option<usize> {
        self.entries.iter().position(|e| e.is_none())
    }

    /// Return the entry at `idx`.
    pub fn get(&self, idx: usize) -> Option<&MountEntry> {
        self.entries.get(idx)?.as_ref()
    }

    /// Total number of mounted filesystems.
    pub const fn count(&self) -> usize {
        self.count
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn copy_to_field(dst: &mut [u8], src: &[u8]) {
    let len = src.len().min(dst.len() - 1);
    dst[..len].copy_from_slice(&src[..len]);
    dst[len] = 0;
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `mount(2)`.
///
/// # Errors
///
/// | `Error`           | Condition                                      |
/// |-------------------|------------------------------------------------|
/// | `PermissionDenied`| Caller lacks `CAP_SYS_ADMIN`                   |
/// | `InvalidArgument` | Unknown mount flags                             |
/// | `Busy`            | Target already mounted (without `MS_REMOUNT`)   |
/// | `OutOfMemory`     | Mount table is full                             |
pub fn do_mount(
    table: &mut MountTable,
    source: &[u8],
    target: &[u8],
    fstype: &[u8],
    flags: u64,
    cap_sys_admin: bool,
) -> Result<()> {
    if !cap_sys_admin {
        return Err(Error::PermissionDenied);
    }
    if flags & !MS_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }

    let is_remount = flags & MS_REMOUNT != 0;
    let is_bind = flags & MS_BIND != 0;

    if let Some(idx) = table.find_by_target(target) {
        if is_remount {
            // Update flags on existing mount.
            if let Some(entry) = table.entries[idx].as_mut() {
                entry.flags = flags & !MS_REMOUNT;
            }
            return Ok(());
        }
        return Err(Error::Busy);
    }

    if is_remount {
        // Remounting non-existent mount.
        return Err(Error::InvalidArgument);
    }

    let slot = table.alloc_slot().ok_or(Error::OutOfMemory)?;
    let mut entry = MountEntry {
        source: [0u8; 256],
        target: [0u8; 256],
        fstype: [0u8; 32],
        flags,
        is_bind,
    };
    copy_to_field(&mut entry.source, source);
    copy_to_field(&mut entry.target, target);
    copy_to_field(&mut entry.fstype, fstype);
    table.entries[slot] = Some(entry);
    table.count += 1;
    Ok(())
}

/// Handler for `umount2(2)`.
///
/// # Errors
///
/// | `Error`           | Condition                                  |
/// |-------------------|--------------------------------------------|
/// | `PermissionDenied`| Caller lacks `CAP_SYS_ADMIN`               |
/// | `InvalidArgument` | Unknown flags                               |
/// | `NotFound`        | Target is not mounted (`EINVAL` in Linux)   |
/// | `Busy`            | Target is busy and `MNT_FORCE` not set     |
pub fn do_umount2(
    table: &mut MountTable,
    target: &[u8],
    flags: i32,
    cap_sys_admin: bool,
    is_busy: bool,
) -> Result<()> {
    if !cap_sys_admin {
        return Err(Error::PermissionDenied);
    }
    if flags & !MNT_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }

    let idx = table.find_by_target(target).ok_or(Error::NotFound)?;

    if is_busy && flags & MNT_FORCE == 0 && flags & MNT_DETACH == 0 {
        return Err(Error::Busy);
    }

    table.entries[idx] = None;
    table.count -= 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_ok() {
        let mut t = MountTable::new();
        do_mount(&mut t, b"/dev/sda1", b"/mnt", b"ext4", 0, true).unwrap();
        assert_eq!(t.count(), 1);
    }

    #[test]
    fn mount_no_cap() {
        let mut t = MountTable::new();
        assert_eq!(
            do_mount(&mut t, b"/dev/sda1", b"/mnt", b"ext4", 0, false),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn mount_busy() {
        let mut t = MountTable::new();
        do_mount(&mut t, b"/dev/sda1", b"/mnt", b"ext4", 0, true).unwrap();
        assert_eq!(
            do_mount(&mut t, b"/dev/sdb1", b"/mnt", b"ext4", 0, true),
            Err(Error::Busy)
        );
    }

    #[test]
    fn umount_ok() {
        let mut t = MountTable::new();
        do_mount(&mut t, b"/dev/sda1", b"/mnt", b"ext4", 0, true).unwrap();
        do_umount2(&mut t, b"/mnt", 0, true, false).unwrap();
        assert_eq!(t.count(), 0);
    }

    #[test]
    fn remount_changes_flags() {
        let mut t = MountTable::new();
        do_mount(&mut t, b"/dev/sda1", b"/mnt", b"ext4", 0, true).unwrap();
        do_mount(
            &mut t,
            b"/dev/sda1",
            b"/mnt",
            b"ext4",
            MS_REMOUNT | MS_RDONLY,
            true,
        )
        .unwrap();
        let idx = t.find_by_target(b"/mnt").unwrap();
        assert!(t.get(idx).unwrap().flags & MS_RDONLY != 0);
    }
}
