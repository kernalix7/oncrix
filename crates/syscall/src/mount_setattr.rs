// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `mount_setattr(2)` syscall handler.
//!
//! `mount_setattr` (Linux 5.12) allows setting or clearing mount attributes
//! atomically across an entire mount tree without requiring a sequence of
//! individual `mount(2)` calls.  Unlike the old `MS_*` flags passed to
//! `mount(2)`, this interface uses a versioned in-memory structure
//! (`MountAttr`) that can be extended over time.
//!
//! # Key features
//!
//! - Atomic: all changes apply together or none apply.
//! - Propagation aware: apply recursively down a subtree with `AT_RECURSIVE`.
//! - Time namespace aware: change the idmapping / time namespace.
//! - Userns idmapping: associate a user-namespace file descriptor for ID-mapped mounts.
//!
//! # Kernel data flow
//!
//! ```text
//! user space                        kernel space
//! ──────────                        ─────────────
//! mount_setattr(dfd, path,          copy_from_user(MountAttr, usize)
//!               flags, attr, size)  resolve dfd + path → mount
//!                                   validate_attr_changes()
//!                                   apply_attr_changes() [recursive]
//!                               ◄── 0 / -errno
//! ```
//!
//! # References
//!
//! - Linux: `fs/namespace.c` — `do_mount_setattr()`
//! - `include/uapi/linux/mount.h` — `struct mount_attr`
//! - man-pages: `mount_setattr(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// AT_* flags for the `flags` argument
// ---------------------------------------------------------------------------

/// Operate relative to the directory file descriptor `dfd`.
pub const AT_EMPTY_PATH: u32 = 0x1000;
/// Apply the attribute change recursively to the entire mount subtree.
pub const AT_RECURSIVE: u32 = 0x8000;
/// Interpret `path` as a symbolic link target (do not follow it).
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x0100;
/// Do not automount terminals at the final component.
pub const AT_NO_AUTOMOUNT: u32 = 0x0800;

/// All recognised `flags` bits.
const AT_FLAGS_KNOWN: u32 = AT_EMPTY_PATH | AT_RECURSIVE | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT;

// ---------------------------------------------------------------------------
// MOUNT_ATTR_* attribute flags (attr_set / attr_clr bitmasks)
// ---------------------------------------------------------------------------

/// Mount is read-only.
pub const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
/// Do not honour set-user-ID/set-group-ID bits on exec.
pub const MOUNT_ATTR_NOSUID: u64 = 0x0000_0002;
/// Do not interpret character or block special devices.
pub const MOUNT_ATTR_NODEV: u64 = 0x0000_0004;
/// Do not allow programs to be executed from this mount.
pub const MOUNT_ATTR_NOEXEC: u64 = 0x0000_0008;
/// Do not update access times.
pub const MOUNT_ATTR_NOATIME: u64 = 0x0000_0010;
/// Update access times only on write or if atime < mtime.
pub const MOUNT_ATTR_RELATIME: u64 = 0x0000_0020;
/// Always update access times (override relatime/noatime).
pub const MOUNT_ATTR_STRICTATIME: u64 = 0x0000_0030;
/// Atime mask: the three atime bits are mutually exclusive.
pub const MOUNT_ATTR_ATIME_MASK: u64 = 0x0000_0070;
/// Do not follow symbolic links.
pub const MOUNT_ATTR_NOSYMFOLLOW: u64 = 0x0000_0200;
/// Use an ID-mapped user namespace (requires `userns_fd`).
pub const MOUNT_ATTR_IDMAP: u64 = 0x0010_0000;

/// All recognised attribute bits (set + clr).
const MOUNT_ATTR_ALL: u64 = MOUNT_ATTR_RDONLY
    | MOUNT_ATTR_NOSUID
    | MOUNT_ATTR_NODEV
    | MOUNT_ATTR_NOEXEC
    | MOUNT_ATTR_ATIME_MASK
    | MOUNT_ATTR_NOSYMFOLLOW
    | MOUNT_ATTR_IDMAP;

// ---------------------------------------------------------------------------
// MountAttr — the in-memory argument structure
// ---------------------------------------------------------------------------

/// Minimum valid structure size (version 0: `attr_set` through `userns_fd`).
///
/// `mount_setattr` uses extensible structures; the kernel rejects any size
/// that is smaller than this or larger than `sizeof(MountAttr)`.
pub const MOUNT_ATTR_SIZE_VER0: usize = 32;

/// Argument structure passed to `mount_setattr(2)`.
///
/// Matches `struct mount_attr` from `include/uapi/linux/mount.h`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MountAttr {
    /// Bitmask of mount attributes to set.
    pub attr_set: u64,
    /// Bitmask of mount attributes to clear.
    pub attr_clr: u64,
    /// Mount propagation type (see `MOUNT_ATTR_PROPAGATION_*`).
    pub propagation: u64,
    /// File descriptor of the user namespace for ID-mapped mounts.
    /// Valid only when `MOUNT_ATTR_IDMAP` is in `attr_set`.
    pub userns_fd: u64,
}

// ---------------------------------------------------------------------------
// Mount propagation constants
// ---------------------------------------------------------------------------

/// Do not propagate mount events.
pub const MS_PRIVATE: u64 = 0x0004_0000;
/// Slave propagation: receive events from master.
pub const MS_SLAVE: u64 = 0x0008_0000;
/// Shared propagation: bidirectional event sharing.
pub const MS_SHARED: u64 = 0x0010_0000;
/// Unbindable: cannot be bind-mounted.
pub const MS_UNBINDABLE: u64 = 0x0002_0000;

/// Zero means "do not change propagation".
const PROPAGATION_NONE: u64 = 0;

// ---------------------------------------------------------------------------
// Mount record for the stub table
// ---------------------------------------------------------------------------

/// Maximum number of mounts in the stub mount table.
pub const MAX_MOUNTS: usize = 128;

/// Current attribute state of a mount.
#[derive(Debug, Clone, Copy, Default)]
pub struct MountAttrs {
    /// Active attribute flags (combination of `MOUNT_ATTR_*`).
    pub flags: u64,
    /// Propagation mode (one of `MS_PRIVATE`, `MS_SLAVE`, etc.; 0 = shared by default).
    pub propagation: u64,
    /// User-namespace FD for ID-mapped mounts (-1 if none).
    pub userns_fd: i32,
}

/// A record representing one mount point.
#[derive(Debug, Clone, Copy)]
pub struct MountRecord {
    /// Synthetic mount ID.
    pub id: u32,
    /// Parent mount ID (0 for the root mount).
    pub parent_id: u32,
    /// Current attributes.
    pub attrs: MountAttrs,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl MountRecord {
    /// Create an empty, unused slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            parent_id: 0,
            attrs: MountAttrs {
                flags: 0,
                propagation: 0,
                userns_fd: -1,
            },
            in_use: false,
        }
    }
}

/// Stub mount table.
pub struct MountTable {
    mounts: [MountRecord; MAX_MOUNTS],
    count: usize,
}

impl MountTable {
    /// Create an empty mount table.
    pub const fn new() -> Self {
        Self {
            mounts: [const { MountRecord::empty() }; MAX_MOUNTS],
            count: 0,
        }
    }

    /// Insert a new mount record.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfMemory`] — table is full.
    pub fn insert(&mut self, record: MountRecord) -> Result<()> {
        for slot in self.mounts.iter_mut() {
            if !slot.in_use {
                *slot = record;
                slot.in_use = true;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find a mount by ID.
    pub fn find(&self, id: u32) -> Option<&MountRecord> {
        self.mounts.iter().find(|m| m.in_use && m.id == id)
    }

    /// Find a mount by ID (mutable).
    pub fn find_mut(&mut self, id: u32) -> Option<&mut MountRecord> {
        self.mounts.iter_mut().find(|m| m.in_use && m.id == id)
    }

    /// Collect IDs of all mounts with the given parent (for recursive apply).
    ///
    /// Writes up to `buf.len()` IDs into `buf` and returns the count.
    pub fn children_of(&self, parent_id: u32, buf: &mut [u32]) -> usize {
        let mut n = 0;
        for m in self.mounts.iter() {
            if n >= buf.len() {
                break;
            }
            if m.in_use && m.parent_id == parent_id {
                buf[n] = m.id;
                n += 1;
            }
        }
        n
    }

    /// Return the total number of active mounts.
    pub const fn count(&self) -> usize {
        self.count
    }
}

// ---------------------------------------------------------------------------
// Attribute validation helpers
// ---------------------------------------------------------------------------

/// Validate the `MountAttr` structure contents.
fn validate_mount_attr(attr: &MountAttr, size: usize) -> Result<()> {
    // Size must be at least version-0 minimum and no larger than the struct.
    let max_size = core::mem::size_of::<MountAttr>();
    if size < MOUNT_ATTR_SIZE_VER0 || size > max_size {
        return Err(Error::InvalidArgument);
    }

    // Unknown bits in attr_set.
    if attr.attr_set & !MOUNT_ATTR_ALL != 0 {
        return Err(Error::InvalidArgument);
    }

    // Unknown bits in attr_clr.
    if attr.attr_clr & !MOUNT_ATTR_ALL != 0 {
        return Err(Error::InvalidArgument);
    }

    // attr_set and attr_clr must not overlap (except for atime bits which are
    // replaced, not OR'd — the kernel treats them as a field).
    let non_atime_set = attr.attr_set & !MOUNT_ATTR_ATIME_MASK;
    let non_atime_clr = attr.attr_clr & !MOUNT_ATTR_ATIME_MASK;
    if non_atime_set & non_atime_clr != 0 {
        return Err(Error::InvalidArgument);
    }

    // Atime mode must be one of the three valid values (or zero = no change).
    let atime = attr.attr_set & MOUNT_ATTR_ATIME_MASK;
    if atime != 0
        && atime != MOUNT_ATTR_NOATIME
        && atime != MOUNT_ATTR_RELATIME
        && atime != MOUNT_ATTR_STRICTATIME
    {
        return Err(Error::InvalidArgument);
    }

    // IDMAP requires a valid userns_fd.
    if attr.attr_set & MOUNT_ATTR_IDMAP != 0 && attr.userns_fd == 0 {
        return Err(Error::InvalidArgument);
    }

    // Cannot clear IDMAP (ID-mapped mounts are permanent).
    if attr.attr_clr & MOUNT_ATTR_IDMAP != 0 {
        return Err(Error::InvalidArgument);
    }

    // Validate propagation value.
    if attr.propagation != PROPAGATION_NONE
        && attr.propagation != MS_PRIVATE
        && attr.propagation != MS_SLAVE
        && attr.propagation != MS_SHARED
        && attr.propagation != MS_UNBINDABLE
    {
        return Err(Error::InvalidArgument);
    }

    Ok(())
}

/// Validate the `flags` argument.
fn validate_flags(flags: u32) -> Result<()> {
    if flags & !AT_FLAGS_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Apply attributes to a single mount
// ---------------------------------------------------------------------------

/// Apply `attr` changes to a single mount record.
fn apply_to_mount(record: &mut MountRecord, attr: &MountAttr) {
    // Clear bits first, then set (so set wins on atime mask).
    record.attrs.flags &= !attr.attr_clr;
    // For atime: clear the whole mask and apply new value.
    record.attrs.flags &= !MOUNT_ATTR_ATIME_MASK;
    let new_atime = attr.attr_set & MOUNT_ATTR_ATIME_MASK;
    let other_set = attr.attr_set & !MOUNT_ATTR_ATIME_MASK;
    record.attrs.flags |= other_set | new_atime;

    // Apply propagation if requested.
    if attr.propagation != PROPAGATION_NONE {
        record.attrs.propagation = attr.propagation;
    }

    // Apply userns_fd if IDMAP is being set.
    if attr.attr_set & MOUNT_ATTR_IDMAP != 0 {
        record.attrs.userns_fd = attr.userns_fd as i32;
    }
}

// ---------------------------------------------------------------------------
// do_mount_setattr — main handler
// ---------------------------------------------------------------------------

/// Handler for `mount_setattr(2)`.
///
/// Applies `attr` changes to the mount identified by `mount_id` in `table`.
/// If `AT_RECURSIVE` is set in `flags`, the changes are propagated to all
/// mounts in the subtree rooted at `mount_id`.
///
/// # Arguments
///
/// * `table`     — Mount table.
/// * `mount_id`  — ID of the target mount point.
/// * `flags`     — `AT_*` flags controlling resolution behaviour.
/// * `attr`      — Attribute changes to apply.
/// * `attr_size` — Size the caller passed (version check).
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — Bad flags or invalid attribute values.
/// - [`Error::NotFound`]        — No mount with `mount_id` exists.
/// - [`Error::PermissionDenied`] — Caller lacks `CAP_SYS_ADMIN` (stub: always ok).
pub fn do_mount_setattr(
    table: &mut MountTable,
    mount_id: u32,
    flags: u32,
    attr: &MountAttr,
    attr_size: usize,
) -> Result<()> {
    validate_flags(flags)?;
    validate_mount_attr(attr, attr_size)?;

    // Verify the root mount exists.
    if table.find(mount_id).is_none() {
        return Err(Error::NotFound);
    }

    // Collect the IDs to update (BFS over the subtree).
    let recursive = flags & AT_RECURSIVE != 0;
    apply_recursive(table, mount_id, attr, recursive)
}

/// Apply attribute changes to `id` and optionally all descendants.
fn apply_recursive(
    table: &mut MountTable,
    id: u32,
    attr: &MountAttr,
    recursive: bool,
) -> Result<()> {
    // Apply to the root mount.
    if let Some(record) = table.find_mut(id) {
        apply_to_mount(record, attr);
    } else {
        return Err(Error::NotFound);
    }

    if !recursive {
        return Ok(());
    }

    // Collect children to avoid borrowing conflicts.
    let mut child_buf = [0u32; MAX_MOUNTS];
    let n = table.children_of(id, &mut child_buf);
    let child_ids: [u32; MAX_MOUNTS] = child_buf;
    let child_count = n;

    for &cid in &child_ids[..child_count] {
        apply_recursive(table, cid, attr, true)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_table_with_tree() -> MountTable {
        let mut t = MountTable::new();
        // Root mount (id=1)
        t.insert(MountRecord {
            id: 1,
            parent_id: 0,
            attrs: MountAttrs {
                flags: 0,
                propagation: 0,
                userns_fd: -1,
            },
            in_use: true,
        })
        .unwrap();
        // Child mount (id=2, parent=1)
        t.insert(MountRecord {
            id: 2,
            parent_id: 1,
            attrs: MountAttrs {
                flags: 0,
                propagation: 0,
                userns_fd: -1,
            },
            in_use: true,
        })
        .unwrap();
        // Grandchild (id=3, parent=2)
        t.insert(MountRecord {
            id: 3,
            parent_id: 2,
            attrs: MountAttrs {
                flags: 0,
                propagation: 0,
                userns_fd: -1,
            },
            in_use: true,
        })
        .unwrap();
        t
    }

    fn attr_set_rdonly() -> MountAttr {
        MountAttr {
            attr_set: MOUNT_ATTR_RDONLY,
            attr_clr: 0,
            propagation: 0,
            userns_fd: 0,
        }
    }

    #[test]
    fn set_rdonly_single_mount() {
        let mut t = make_table_with_tree();
        let attr = attr_set_rdonly();
        do_mount_setattr(&mut t, 1, 0, &attr, MOUNT_ATTR_SIZE_VER0).unwrap();
        assert_eq!(
            t.find(1).unwrap().attrs.flags & MOUNT_ATTR_RDONLY,
            MOUNT_ATTR_RDONLY
        );
        // Child should not be affected.
        assert_eq!(t.find(2).unwrap().attrs.flags & MOUNT_ATTR_RDONLY, 0);
    }

    #[test]
    fn set_rdonly_recursive() {
        let mut t = make_table_with_tree();
        let attr = attr_set_rdonly();
        do_mount_setattr(&mut t, 1, AT_RECURSIVE, &attr, MOUNT_ATTR_SIZE_VER0).unwrap();
        assert_eq!(
            t.find(1).unwrap().attrs.flags & MOUNT_ATTR_RDONLY,
            MOUNT_ATTR_RDONLY
        );
        assert_eq!(
            t.find(2).unwrap().attrs.flags & MOUNT_ATTR_RDONLY,
            MOUNT_ATTR_RDONLY
        );
        assert_eq!(
            t.find(3).unwrap().attrs.flags & MOUNT_ATTR_RDONLY,
            MOUNT_ATTR_RDONLY
        );
    }

    #[test]
    fn clear_rdonly() {
        let mut t = make_table_with_tree();
        // First set it.
        let set = MountAttr {
            attr_set: MOUNT_ATTR_RDONLY,
            ..MountAttr::default()
        };
        do_mount_setattr(&mut t, 1, 0, &set, MOUNT_ATTR_SIZE_VER0).unwrap();
        // Then clear it.
        let clr = MountAttr {
            attr_clr: MOUNT_ATTR_RDONLY,
            ..MountAttr::default()
        };
        do_mount_setattr(&mut t, 1, 0, &clr, MOUNT_ATTR_SIZE_VER0).unwrap();
        assert_eq!(t.find(1).unwrap().attrs.flags & MOUNT_ATTR_RDONLY, 0);
    }

    #[test]
    fn mount_not_found() {
        let mut t = make_table_with_tree();
        let attr = attr_set_rdonly();
        assert_eq!(
            do_mount_setattr(&mut t, 99, 0, &attr, MOUNT_ATTR_SIZE_VER0),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn unknown_attr_set_rejected() {
        let mut t = make_table_with_tree();
        let attr = MountAttr {
            attr_set: 0xDEAD_0000_0000,
            ..MountAttr::default()
        };
        assert_eq!(
            do_mount_setattr(&mut t, 1, 0, &attr, MOUNT_ATTR_SIZE_VER0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn overlapping_set_clr_rejected() {
        let mut t = make_table_with_tree();
        let attr = MountAttr {
            attr_set: MOUNT_ATTR_RDONLY,
            attr_clr: MOUNT_ATTR_RDONLY,
            ..MountAttr::default()
        };
        assert_eq!(
            do_mount_setattr(&mut t, 1, 0, &attr, MOUNT_ATTR_SIZE_VER0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn invalid_atime_combination_rejected() {
        let mut t = make_table_with_tree();
        // Set all three atime bits simultaneously — invalid.
        let attr = MountAttr {
            attr_set: MOUNT_ATTR_NOATIME | MOUNT_ATTR_RELATIME,
            ..MountAttr::default()
        };
        assert_eq!(
            do_mount_setattr(&mut t, 1, 0, &attr, MOUNT_ATTR_SIZE_VER0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn idmap_requires_userns_fd() {
        let mut t = make_table_with_tree();
        let attr = MountAttr {
            attr_set: MOUNT_ATTR_IDMAP,
            userns_fd: 0,
            ..MountAttr::default()
        };
        assert_eq!(
            do_mount_setattr(&mut t, 1, 0, &attr, MOUNT_ATTR_SIZE_VER0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn cannot_clear_idmap() {
        let mut t = make_table_with_tree();
        let attr = MountAttr {
            attr_clr: MOUNT_ATTR_IDMAP,
            ..MountAttr::default()
        };
        assert_eq!(
            do_mount_setattr(&mut t, 1, 0, &attr, MOUNT_ATTR_SIZE_VER0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn propagation_set_on_mount() {
        let mut t = make_table_with_tree();
        let attr = MountAttr {
            propagation: MS_PRIVATE,
            ..MountAttr::default()
        };
        do_mount_setattr(&mut t, 1, 0, &attr, MOUNT_ATTR_SIZE_VER0).unwrap();
        assert_eq!(t.find(1).unwrap().attrs.propagation, MS_PRIVATE);
    }

    #[test]
    fn invalid_flags_rejected() {
        let mut t = make_table_with_tree();
        let attr = MountAttr::default();
        assert_eq!(
            do_mount_setattr(&mut t, 1, 0xFFFF_0000, &attr, MOUNT_ATTR_SIZE_VER0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn size_too_small_rejected() {
        let mut t = make_table_with_tree();
        let attr = MountAttr::default();
        assert_eq!(
            do_mount_setattr(&mut t, 1, 0, &attr, 8),
            Err(Error::InvalidArgument)
        );
    }
}
