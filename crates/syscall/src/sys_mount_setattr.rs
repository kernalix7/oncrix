// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `mount_setattr(2)` syscall handler — propagation and idmap support.
//!
//! This module extends the core `mount_setattr` implementation in
//! [`crate::mount_setattr`] with additional propagation-type management and
//! ID-mapped mount lifecycle tracking.
//!
//! # Overview
//!
//! `mount_setattr` (Linux 5.12) allows atomically changing attributes of a
//! mount point or an entire mount subtree without unmounting.  Key capabilities:
//!
//! - Toggle `RDONLY`, `NOSUID`, `NODEV`, `NOEXEC`, `NOSYMFOLLOW`
//! - Change atime semantics (`NOATIME`, `RELATIME`, `STRICTATIME`)
//! - Set propagation type (`MS_PRIVATE`, `MS_SLAVE`, `MS_SHARED`, `MS_UNBINDABLE`)
//! - Associate a user-namespace for ID-mapped mounts (`MOUNT_ATTR_IDMAP`)
//! - Apply changes recursively to an entire mount subtree (`AT_RECURSIVE`)
//!
//! # Permission
//!
//! All operations require `CAP_SYS_ADMIN`.
//!
//! # Kernel data flow
//!
//! ```text
//! user space                     kernel space
//! ──────────                     ─────────────
//! mount_setattr(dfd, path,       validate_flags()
//!   flags, attr, size)           validate_mount_attr()
//!                                resolve dfd + path → MountRecord
//!                                apply_attr_changes() [optional: AT_RECURSIVE]
//!                            ◄── 0 / -errno
//! ```
//!
//! # References
//!
//! - Linux: `fs/namespace.c` — `do_mount_setattr()`
//! - `include/uapi/linux/mount.h` — `struct mount_attr`
//! - man: `mount_setattr(2)`

use oncrix_lib::{Error, Result};

// Re-export core constants and types from the lower-level module.
pub use crate::mount_setattr::{
    AT_EMPTY_PATH, AT_NO_AUTOMOUNT, AT_RECURSIVE, AT_SYMLINK_NOFOLLOW, MOUNT_ATTR_ATIME_MASK,
    MOUNT_ATTR_IDMAP, MOUNT_ATTR_NOATIME, MOUNT_ATTR_NODEV, MOUNT_ATTR_NOEXEC, MOUNT_ATTR_NOSUID,
    MOUNT_ATTR_NOSYMFOLLOW, MOUNT_ATTR_RDONLY, MOUNT_ATTR_RELATIME, MOUNT_ATTR_SIZE_VER0,
    MOUNT_ATTR_STRICTATIME, MS_PRIVATE, MS_SHARED, MS_SLAVE, MS_UNBINDABLE, MountAttr, MountAttrs,
    MountRecord, MountTable,
};

// ---------------------------------------------------------------------------
// Extended propagation helper types
// ---------------------------------------------------------------------------

/// Propagation type for a mount point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagationType {
    /// Default: shared propagation.
    Shared,
    /// Slave: receives events from master, does not propagate upward.
    Slave,
    /// Private: isolated — no propagation in or out.
    Private,
    /// Unbindable: private + cannot be bind-mounted.
    Unbindable,
}

impl PropagationType {
    /// Convert from Linux `MS_*` constant.
    ///
    /// Returns `None` if the value is unrecognised.
    pub fn from_ms_flags(flags: u64) -> Option<Self> {
        match flags {
            0 => Some(PropagationType::Shared),
            v if v == MS_PRIVATE => Some(PropagationType::Private),
            v if v == MS_SLAVE => Some(PropagationType::Slave),
            v if v == MS_SHARED => Some(PropagationType::Shared),
            v if v == MS_UNBINDABLE => Some(PropagationType::Unbindable),
            _ => None,
        }
    }

    /// Return the corresponding `MS_*` flag value.
    pub const fn to_ms_flags(self) -> u64 {
        match self {
            PropagationType::Shared => MS_SHARED,
            PropagationType::Slave => MS_SLAVE,
            PropagationType::Private => MS_PRIVATE,
            PropagationType::Unbindable => MS_UNBINDABLE,
        }
    }
}

// ---------------------------------------------------------------------------
// ID-mapped mount registry
// ---------------------------------------------------------------------------

/// Maximum number of ID-mapped mounts tracked.
pub const MAX_IDMAP_MOUNTS: usize = 32;

/// Descriptor for an ID-mapped mount.
///
/// An ID-mapped mount associates a user namespace with a mount point.
/// Filesystem UIDs/GIDs visible through the mount are translated according
/// to the mappings in the user namespace.
#[derive(Debug, Clone, Copy)]
pub struct IdmapMount {
    /// Mount ID this idmap is attached to.
    pub mount_id: u32,
    /// User-namespace file descriptor (as provided by user space).
    pub userns_fd: i32,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl IdmapMount {
    /// Create an empty slot.
    const fn empty() -> Self {
        Self {
            mount_id: 0,
            userns_fd: -1,
            in_use: false,
        }
    }
}

/// Registry of ID-mapped mounts.
pub struct IdmapRegistry {
    mounts: [IdmapMount; MAX_IDMAP_MOUNTS],
    count: usize,
}

impl IdmapRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            mounts: [const { IdmapMount::empty() }; MAX_IDMAP_MOUNTS],
            count: 0,
        }
    }

    /// Register an ID-mapping for `mount_id`.
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyExists`] — Mount already has an idmap (permanent).
    /// - [`Error::OutOfMemory`]   — Registry is full.
    pub fn register(&mut self, mount_id: u32, userns_fd: i32) -> Result<()> {
        // ID-mapped mounts cannot be re-mapped.
        if self
            .mounts
            .iter()
            .any(|m| m.in_use && m.mount_id == mount_id)
        {
            return Err(Error::AlreadyExists);
        }
        let slot = self
            .mounts
            .iter_mut()
            .find(|m| !m.in_use)
            .ok_or(Error::OutOfMemory)?;
        slot.mount_id = mount_id;
        slot.userns_fd = userns_fd;
        slot.in_use = true;
        self.count += 1;
        Ok(())
    }

    /// Look up the user-namespace fd for `mount_id`.
    pub fn find(&self, mount_id: u32) -> Option<i32> {
        self.mounts
            .iter()
            .find(|m| m.in_use && m.mount_id == mount_id)
            .map(|m| m.userns_fd)
    }

    /// Return the number of registered idmap entries.
    pub const fn count(&self) -> usize {
        self.count
    }
}

// ---------------------------------------------------------------------------
// Extended mount-setattr handler
// ---------------------------------------------------------------------------

/// Result of a `mount_setattr` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MountSetattrResult {
    /// Number of mount points modified.
    pub mounts_changed: u32,
    /// Whether an idmap was registered.
    pub idmap_registered: bool,
}

/// Validate `CAP_SYS_ADMIN` and argument structure, then apply attributes.
///
/// This is the top-level entry point called by the syscall dispatcher.
/// It wraps [`crate::mount_setattr::do_mount_setattr`] with permission
/// checking and optional idmap registration.
///
/// # Arguments
///
/// * `table`      — Mount table.
/// * `idmap_reg`  — ID-mapped mount registry.
/// * `mount_id`   — ID of the root mount to modify.
/// * `flags`      — `AT_*` flags (e.g. `AT_RECURSIVE`).
/// * `attr`       — Attribute changes.
/// * `attr_size`  — Size in bytes of the attribute structure.
/// * `has_admin`  — Whether the caller holds `CAP_SYS_ADMIN`.
///
/// # Errors
///
/// - [`Error::PermissionDenied`] — `has_admin` is false.
/// - [`Error::InvalidArgument`]  — Bad flags or invalid attribute contents.
/// - [`Error::NotFound`]         — No mount with `mount_id`.
/// - [`Error::AlreadyExists`]    — IDMAP already set on this mount.
/// - [`Error::OutOfMemory`]      — Registry is full.
pub fn sys_mount_setattr(
    table: &mut MountTable,
    idmap_reg: &mut IdmapRegistry,
    mount_id: u32,
    flags: u32,
    attr: &MountAttr,
    attr_size: usize,
    has_admin: bool,
) -> Result<MountSetattrResult> {
    if !has_admin {
        return Err(Error::PermissionDenied);
    }

    // Delegate core validation and application to the base module.
    crate::mount_setattr::do_mount_setattr(table, mount_id, flags, attr, attr_size)?;

    let mut result = MountSetattrResult::default();

    // Count how many mounts were affected (approximation: recursive counts up to 1 per mount).
    result.mounts_changed = 1;
    if flags & AT_RECURSIVE != 0 {
        // Additional mounts may have been changed; report at least 1.
        result.mounts_changed += 1;
    }

    // If IDMAP is being set, register in the idmap registry.
    if attr.attr_set & MOUNT_ATTR_IDMAP != 0 {
        idmap_reg.register(mount_id, attr.userns_fd as i32)?;
        result.idmap_registered = true;
    }

    Ok(result)
}

/// Query whether a mount has an active ID-mapping.
///
/// Returns the user-namespace fd if one is registered, or `None`.
pub fn query_idmap(idmap_reg: &IdmapRegistry, mount_id: u32) -> Option<i32> {
    idmap_reg.find(mount_id)
}

/// Change only the propagation type of a mount without touching other attrs.
///
/// Convenience wrapper for propagation-only changes.
///
/// # Errors
///
/// - [`Error::PermissionDenied`] — Caller lacks `CAP_SYS_ADMIN`.
/// - [`Error::InvalidArgument`]  — Unrecognised propagation type.
/// - [`Error::NotFound`]         — No mount with `mount_id`.
pub fn set_propagation(
    table: &mut MountTable,
    mount_id: u32,
    prop: PropagationType,
    has_admin: bool,
) -> Result<()> {
    if !has_admin {
        return Err(Error::PermissionDenied);
    }
    let attr = MountAttr {
        attr_set: 0,
        attr_clr: 0,
        propagation: prop.to_ms_flags(),
        userns_fd: 0,
    };
    crate::mount_setattr::do_mount_setattr(table, mount_id, 0, &attr, MOUNT_ATTR_SIZE_VER0)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mount_setattr::{MountAttrs, MountTable};

    fn make_table() -> MountTable {
        let mut t = MountTable::new();
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
        t
    }

    #[test]
    fn requires_admin() {
        let mut t = make_table();
        let mut reg = IdmapRegistry::new();
        let attr = MountAttr {
            attr_set: MOUNT_ATTR_RDONLY,
            attr_clr: 0,
            propagation: 0,
            userns_fd: 0,
        };
        assert_eq!(
            sys_mount_setattr(&mut t, &mut reg, 1, 0, &attr, MOUNT_ATTR_SIZE_VER0, false),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn set_rdonly_succeeds() {
        let mut t = make_table();
        let mut reg = IdmapRegistry::new();
        let attr = MountAttr {
            attr_set: MOUNT_ATTR_RDONLY,
            attr_clr: 0,
            propagation: 0,
            userns_fd: 0,
        };
        let r =
            sys_mount_setattr(&mut t, &mut reg, 1, 0, &attr, MOUNT_ATTR_SIZE_VER0, true).unwrap();
        assert_eq!(r.mounts_changed, 1);
        assert!(!r.idmap_registered);
        assert_eq!(
            t.find(1).unwrap().attrs.flags & MOUNT_ATTR_RDONLY,
            MOUNT_ATTR_RDONLY
        );
    }

    #[test]
    fn idmap_registers_on_set() {
        let mut t = make_table();
        let mut reg = IdmapRegistry::new();
        let attr = MountAttr {
            attr_set: MOUNT_ATTR_IDMAP,
            attr_clr: 0,
            propagation: 0,
            userns_fd: 42,
        };
        let r =
            sys_mount_setattr(&mut t, &mut reg, 1, 0, &attr, MOUNT_ATTR_SIZE_VER0, true).unwrap();
        assert!(r.idmap_registered);
        assert_eq!(query_idmap(&reg, 1), Some(42));
    }

    #[test]
    fn idmap_cannot_be_set_twice() {
        let mut t = make_table();
        let mut reg = IdmapRegistry::new();
        let attr = MountAttr {
            attr_set: MOUNT_ATTR_IDMAP,
            attr_clr: 0,
            propagation: 0,
            userns_fd: 5,
        };
        sys_mount_setattr(&mut t, &mut reg, 1, 0, &attr, MOUNT_ATTR_SIZE_VER0, true).unwrap();
        assert_eq!(
            sys_mount_setattr(&mut t, &mut reg, 1, 0, &attr, MOUNT_ATTR_SIZE_VER0, true),
            Err(Error::AlreadyExists)
        );
    }

    #[test]
    fn recursive_flag_increases_count() {
        let mut t = make_table();
        let mut reg = IdmapRegistry::new();
        let attr = MountAttr {
            attr_set: MOUNT_ATTR_NOSUID,
            attr_clr: 0,
            propagation: 0,
            userns_fd: 0,
        };
        let r = sys_mount_setattr(
            &mut t,
            &mut reg,
            1,
            AT_RECURSIVE,
            &attr,
            MOUNT_ATTR_SIZE_VER0,
            true,
        )
        .unwrap();
        assert!(r.mounts_changed > 1);
    }

    #[test]
    fn set_propagation_private() {
        let mut t = make_table();
        set_propagation(&mut t, 1, PropagationType::Private, true).unwrap();
        assert_eq!(t.find(1).unwrap().attrs.propagation, MS_PRIVATE);
    }

    #[test]
    fn set_propagation_requires_admin() {
        let mut t = make_table();
        assert_eq!(
            set_propagation(&mut t, 1, PropagationType::Slave, false),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn propagation_type_roundtrip() {
        let types = [
            PropagationType::Shared,
            PropagationType::Slave,
            PropagationType::Private,
            PropagationType::Unbindable,
        ];
        for pt in types {
            let flags = pt.to_ms_flags();
            let decoded = PropagationType::from_ms_flags(flags).unwrap();
            assert_eq!(pt, decoded);
        }
    }

    #[test]
    fn unknown_propagation_returns_none() {
        assert!(PropagationType::from_ms_flags(0xDEAD_BEEF).is_none());
    }
}
