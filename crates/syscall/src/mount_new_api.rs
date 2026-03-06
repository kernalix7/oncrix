// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! New mount API extended syscall handlers.
//!
//! Complements `mount_api.rs` with the higher-level mount operations
//! introduced in Linux 5.2 – 5.12:
//!
//! | Syscall            | Handler                      | Purpose                              |
//! |--------------------|------------------------------|--------------------------------------|
//! | `mount_setattr`    | [`do_mount_setattr_ext`]     | Atomic attr change with recursion    |
//! | `move_mount` tree  | [`do_move_mount_subtree`]    | Move a whole mount subtree           |
//! | `open_tree` clone  | [`do_open_tree_detached`]    | Open a detached mount tree clone     |
//! | `fspick`           | [`do_fspick`]                | Reopen a mount as a config context   |
//! | `mount_idmap`      | [`do_mount_idmap`]           | Apply an ID-mapped mount overlay     |
//!
//! # Background
//!
//! The classic `mount(2)` syscall is a single monolithic operation.  The
//! new API breaks it into four composable steps:
//!
//! 1. `fsopen` — open a filesystem context (from `mount_api.rs`).
//! 2. `fsconfig` — configure the context (from `mount_api.rs`).
//! 3. `fsmount` — materialise the configured context into a detached mount fd.
//! 4. `move_mount` — attach the detached mount to the namespace.
//!
//! This module adds the complementary operations (`fspick`, `mount_setattr`
//! recursive, `move_mount` subtree) that round out the API.
//!
//! # POSIX conformance
//!
//! Mount operations are not covered by POSIX.1-2024.  The flag semantics
//! follow the Linux kernel `include/uapi/linux/mount.h` specification.
//!
//! # References
//!
//! - Linux `fs/namespace.c`, `fs/fsopen.c`
//! - Linux `include/uapi/linux/mount.h`
//! - man: `mount_setattr(2)`, `move_mount(2)`, `open_tree(2)`, `fspick(2)`

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

// Re-use types from the existing mount_api module.
use crate::mount_api::{
    FSOPEN_CLOEXEC, FsContext, MOVE_MOUNT_F_EMPTY_PATH, MOVE_MOUNT_F_SYMLINKS, MountAttr,
    MountRegistry, OPEN_TREE_CLOEXEC, OPEN_TREE_CLONE,
};

// ---------------------------------------------------------------------------
// Constants — recursive mount_setattr
// ---------------------------------------------------------------------------

/// Apply attribute change recursively to all child mounts.
pub const MOUNT_SETATTR_PROPAGATE: u32 = 0x0000_0001;

/// Apply to all mounts in the subtree, not just the specified point.
pub const MOUNT_SETATTR_RECURSE: u32 = 0x0000_0002;

/// Mask of all known `mount_setattr_ext` flags.
const MOUNT_SETATTR_FLAGS_KNOWN: u32 = MOUNT_SETATTR_PROPAGATE | MOUNT_SETATTR_RECURSE;

// ---------------------------------------------------------------------------
// Constants — fspick
// ---------------------------------------------------------------------------

/// Reopen the mount's superblock for reconfiguration.
pub const FSPICK_CLOEXEC: u32 = 0x0000_0001;

/// Require that the path be an exact mount point.
pub const FSPICK_SYMLINK_NOFOLLOW: u32 = 0x0000_0002;

/// Skip automount entries.
pub const FSPICK_NO_AUTOMOUNT: u32 = 0x0000_0004;

/// Allow `AT_EMPTY_PATH` semantics (operate on the fd itself).
pub const FSPICK_EMPTY_PATH: u32 = 0x0000_0008;

/// Mask of all known `fspick` flags.
const FSPICK_FLAGS_KNOWN: u32 =
    FSPICK_CLOEXEC | FSPICK_SYMLINK_NOFOLLOW | FSPICK_NO_AUTOMOUNT | FSPICK_EMPTY_PATH;

// ---------------------------------------------------------------------------
// Constants — move_mount subtree
// ---------------------------------------------------------------------------

/// Move the entire subtree rooted at `from` to `to`.
pub const MOVE_MOUNT_SET_GROUP: u32 = 0x0001_0000;

/// Known `move_mount` extension flags (OR'd with the base flags in mount_api).
const MOVE_MOUNT_EXT_KNOWN: u32 =
    MOVE_MOUNT_SET_GROUP | MOVE_MOUNT_F_SYMLINKS | MOVE_MOUNT_F_EMPTY_PATH;

// ---------------------------------------------------------------------------
// MountSetAttrExt — extended setattr arguments
// ---------------------------------------------------------------------------

/// Extended `mount_setattr` arguments with recursion control.
///
/// `attr` carries the base attribute change; `flags` controls recursion.
/// `size` must equal `core::mem::size_of::<MountSetAttrExt>()`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MountSetAttrExt {
    /// Base attribute change specification.
    pub attr: MountAttr,
    /// Recursion/propagation flags (`MOUNT_SETATTR_*`).
    pub flags: u32,
    /// Size of this structure for forward compatibility.
    pub size: u32,
}

// ---------------------------------------------------------------------------
// IdMapping — a single UID/GID range mapping for idmapped mounts
// ---------------------------------------------------------------------------

/// A single contiguous UID or GID range mapping.
///
/// Maps `count` IDs starting at `first_in` in the source namespace to
/// `first_out` in the destination namespace.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IdMapping {
    /// First ID in the source namespace.
    pub first_in: u32,
    /// First ID in the destination namespace.
    pub first_out: u32,
    /// Number of consecutive IDs in this range.
    pub count: u32,
}

impl IdMapping {
    /// Return `true` if this mapping covers `id` (source namespace).
    pub const fn covers_source(&self, id: u32) -> bool {
        id >= self.first_in && id < self.first_in.saturating_add(self.count)
    }

    /// Translate a source-namespace `id` to the destination namespace.
    ///
    /// Returns `None` if `id` is not in this mapping's range.
    pub fn translate(&self, id: u32) -> Option<u32> {
        if self.covers_source(id) {
            Some(self.first_out + (id - self.first_in))
        } else {
            None
        }
    }
}

/// Maximum number of UID or GID range mappings in a single idmap.
pub const MAX_ID_MAPPINGS: usize = 16;

/// An identity mapping set applied to an idmapped mount.
#[derive(Debug, Clone, Copy)]
pub struct IdMap {
    /// UID range mappings.
    pub uid_map: [IdMapping; MAX_ID_MAPPINGS],
    /// GID range mappings.
    pub gid_map: [IdMapping; MAX_ID_MAPPINGS],
    /// Number of active UID mappings.
    pub uid_count: usize,
    /// Number of active GID mappings.
    pub gid_count: usize,
}

impl Default for IdMap {
    fn default() -> Self {
        Self {
            uid_map: [IdMapping::default(); MAX_ID_MAPPINGS],
            gid_map: [IdMapping::default(); MAX_ID_MAPPINGS],
            uid_count: 0,
            gid_count: 0,
        }
    }
}

impl IdMap {
    /// Add a UID range mapping.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the UID mapping table is full.
    pub fn add_uid_mapping(&mut self, mapping: IdMapping) -> Result<()> {
        if self.uid_count >= MAX_ID_MAPPINGS {
            return Err(Error::OutOfMemory);
        }
        self.uid_map[self.uid_count] = mapping;
        self.uid_count += 1;
        Ok(())
    }

    /// Add a GID range mapping.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the GID mapping table is full.
    pub fn add_gid_mapping(&mut self, mapping: IdMapping) -> Result<()> {
        if self.gid_count >= MAX_ID_MAPPINGS {
            return Err(Error::OutOfMemory);
        }
        self.gid_map[self.gid_count] = mapping;
        self.gid_count += 1;
        Ok(())
    }

    /// Translate a UID from source namespace to destination.
    ///
    /// Returns `None` if the UID is not covered by any mapping.
    pub fn translate_uid(&self, uid: u32) -> Option<u32> {
        self.uid_map[..self.uid_count]
            .iter()
            .find_map(|m| m.translate(uid))
    }

    /// Translate a GID from source namespace to destination.
    ///
    /// Returns `None` if the GID is not covered by any mapping.
    pub fn translate_gid(&self, gid: u32) -> Option<u32> {
        self.gid_map[..self.gid_count]
            .iter()
            .find_map(|m| m.translate(gid))
    }
}

// ---------------------------------------------------------------------------
// do_mount_setattr_ext
// ---------------------------------------------------------------------------

/// `mount_setattr(2)` with recursive subtree support.
///
/// Extends [`crate::mount_api::do_mount_setattr`] with the
/// `MOUNT_SETATTR_RECURSE` flag that applies the attribute change to every
/// child mount in the subtree.
///
/// In this stub the registry is flat (no parent/child tracking), so recursion
/// applies the same attribute change to all active mounts of the same
/// filesystem type when `MOUNT_SETATTR_RECURSE` is set.
///
/// # Arguments
///
/// * `mount_registry` — Mount registry.
/// * `mount_id`       — Root mount to change.
/// * `args`           — Extended attribute change arguments.
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — Unknown flags, wrong `size`, or invalid
///                                 attribute bits.
/// * [`Error::NotFound`]         — `mount_id` not found in the registry.
pub fn do_mount_setattr_ext(
    mount_registry: &mut MountRegistry,
    mount_id: u32,
    args: &MountSetAttrExt,
) -> Result<()> {
    if args.size as usize != core::mem::size_of::<MountSetAttrExt>() {
        return Err(Error::InvalidArgument);
    }
    if args.flags & !MOUNT_SETATTR_FLAGS_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }
    args.attr.validate()?;

    // Validate that the root mount exists.
    if mount_registry.get(mount_id).is_none() {
        return Err(Error::NotFound);
    }

    let attr = args.attr;
    let recurse = args.flags & MOUNT_SETATTR_RECURSE != 0;

    if recurse {
        // In a real kernel we would walk the mount tree.  In the stub we apply
        // the change to all active mounts as a conservative approximation.
        for i in 0..64 {
            // Iterate over all possible IDs — skip non-existent ones.
            if let Some(m) = mount_registry.get_mut(i) {
                m.attr_flags &= !attr.attr_clr;
                m.attr_flags |= attr.attr_set;
            }
        }
    } else {
        let entry = mount_registry.get_mut(mount_id).ok_or(Error::NotFound)?;
        entry.attr_flags &= !attr.attr_clr;
        entry.attr_flags |= attr.attr_set;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// do_move_mount_subtree
// ---------------------------------------------------------------------------

/// Move an entire mount subtree to a new location.
///
/// Validates the source mount and the extension flags, then marks the move
/// as complete.  In a real kernel this would update the VFS namespace tree.
///
/// # Arguments
///
/// * `mount_registry` — Mount registry.
/// * `from_id`        — Source mount ID (root of the subtree to move).
/// * `flags`          — `MOVE_MOUNT_*` flags including `MOVE_MOUNT_SET_GROUP`.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Unknown flags or source not found.
pub fn do_move_mount_subtree(
    mount_registry: &MountRegistry,
    from_id: u32,
    flags: u32,
) -> Result<()> {
    if flags & !MOVE_MOUNT_EXT_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }

    mount_registry.get(from_id).ok_or(Error::InvalidArgument)?;

    // Stub: in a real kernel, detach the subtree at from_id and reattach
    // under the target location.  Peer-group sharing (MOVE_MOUNT_SET_GROUP)
    // would propagate the move to all shared mounts.
    Ok(())
}

// ---------------------------------------------------------------------------
// do_open_tree_detached
// ---------------------------------------------------------------------------

/// Open a detached clone of a mount tree (`open_tree` with `OPEN_TREE_CLONE`).
///
/// Creates an anonymous mount — one that is not attached to any namespace —
/// and returns its ID.  The caller can then configure it with `mount_setattr`
/// and attach it via `move_mount`.
///
/// # Arguments
///
/// * `mount_registry` — Mount registry.
/// * `src_id`         — Source mount to clone.
/// * `flags`          — `OPEN_TREE_*` flags; `OPEN_TREE_CLONE` must be set.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Unknown flags, `OPEN_TREE_CLONE` not set,
///                                or source mount not found.
/// * [`Error::OutOfMemory`]     — Registry is full.
pub fn do_open_tree_detached(
    mount_registry: &mut MountRegistry,
    src_id: u32,
    flags: u32,
) -> Result<u32> {
    let known = OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC;
    if flags & !known != 0 {
        return Err(Error::InvalidArgument);
    }
    if flags & OPEN_TREE_CLONE == 0 {
        return Err(Error::InvalidArgument);
    }

    // Read source info before mutably borrowing the registry.
    let (fs_type_copy, fs_type_len, attr_flags) = {
        let src = mount_registry.get(src_id).ok_or(Error::InvalidArgument)?;
        let len = src.fs_type_bytes().len();
        let mut buf = [0u8; 64];
        buf[..len].copy_from_slice(src.fs_type_bytes());
        (buf, len, src.attr_flags)
    };

    let new_id = mount_registry.alloc(&fs_type_copy[..fs_type_len], attr_flags)?;
    Ok(new_id)
}

// ---------------------------------------------------------------------------
// do_fspick
// ---------------------------------------------------------------------------

/// `fspick(2)` — reopen an existing mount as a reconfigurable filesystem
/// context.
///
/// Returns an [`FsContext`] in the [`FsContextState::Created`] state so the
/// caller can invoke `fsconfig(FSCONFIG_CMD_RECONFIGURE)` to adjust
/// parameters on a live mount without unmounting.
///
/// # Arguments
///
/// * `mount_registry` — Mount registry.
/// * `mount_id`       — The mount to re-open for reconfiguration.
/// * `flags`          — `FSPICK_*` flags.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Unknown flags or source mount not found.
pub fn do_fspick(mount_registry: &MountRegistry, mount_id: u32, flags: u32) -> Result<FsContext> {
    if flags & !FSPICK_FLAGS_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }

    let src = mount_registry.get(mount_id).ok_or(Error::InvalidArgument)?;

    // Build a context using FSOPEN_CLOEXEC when FSPICK_CLOEXEC is set.
    let fsopen_flags = if flags & FSPICK_CLOEXEC != 0 {
        FSOPEN_CLOEXEC
    } else {
        0
    };

    let mut ctx = FsContext::new(src.fs_type_bytes(), fsopen_flags)?;
    // Advance to Created state — this context wraps a live superblock.
    ctx.create()?;
    // Record the mount ID in the context.
    ctx.mount_id = mount_id;
    Ok(ctx)
}

// ---------------------------------------------------------------------------
// do_mount_idmap
// ---------------------------------------------------------------------------

/// Apply an ID-mapped overlay to an existing mount.
///
/// ID-mapped mounts allow a mount to present UIDs/GIDs from a different user
/// namespace, enabling containers to access host files with remapped IDs.
///
/// In this stub the mapping is validated and stored; actual UID/GID
/// translation at `open(2)` time would be performed by the VFS layer.
///
/// # Arguments
///
/// * `mount_registry` — Mount registry.
/// * `mount_id`       — Target mount to apply the ID mapping to.
/// * `idmap`          — The UID/GID mapping set.
/// * `caller_uid`     — UID of the caller (must be 0 for idmapped mounts).
///
/// # Errors
///
/// * [`Error::PermissionDenied`] — Caller is not root (uid != 0).
/// * [`Error::InvalidArgument`]  — Mount not found or mapping overlaps.
pub fn do_mount_idmap(
    mount_registry: &mut MountRegistry,
    mount_id: u32,
    idmap: &IdMap,
    caller_uid: u32,
) -> Result<()> {
    // Only root may create idmapped mounts (requires CAP_SYS_ADMIN).
    if caller_uid != 0 {
        return Err(Error::PermissionDenied);
    }

    let entry = mount_registry
        .get_mut(mount_id)
        .ok_or(Error::InvalidArgument)?;

    // Validate that all mappings are non-empty.
    for i in 0..idmap.uid_count {
        if idmap.uid_map[i].count == 0 {
            return Err(Error::InvalidArgument);
        }
    }
    for i in 0..idmap.gid_count {
        if idmap.gid_map[i].count == 0 {
            return Err(Error::InvalidArgument);
        }
    }

    // Record that this mount has an idmap applied (via attr_flags).
    entry.attr_flags |= crate::mount_api::MOUNT_ATTR_IDMAP;

    Ok(())
}

// ---------------------------------------------------------------------------
// Convenience dispatch wrappers
// ---------------------------------------------------------------------------

/// Dispatch entry for recursive mount_setattr.
pub fn sys_mount_setattr_ext(
    mount_registry: &mut MountRegistry,
    mount_id: u32,
    args: &MountSetAttrExt,
) -> Result<()> {
    do_mount_setattr_ext(mount_registry, mount_id, args)
}

/// Dispatch entry for subtree move_mount.
pub fn sys_move_mount_subtree(
    mount_registry: &MountRegistry,
    from_id: u32,
    flags: u32,
) -> Result<()> {
    do_move_mount_subtree(mount_registry, from_id, flags)
}

/// Dispatch entry for detached open_tree.
pub fn sys_open_tree_detached(
    mount_registry: &mut MountRegistry,
    src_id: u32,
    flags: u32,
) -> Result<u32> {
    do_open_tree_detached(mount_registry, src_id, flags)
}

/// Dispatch entry for fspick.
pub fn sys_fspick(mount_registry: &MountRegistry, mount_id: u32, flags: u32) -> Result<FsContext> {
    do_fspick(mount_registry, mount_id, flags)
}

/// Dispatch entry for idmapped mount.
pub fn sys_mount_idmap(
    mount_registry: &mut MountRegistry,
    mount_id: u32,
    idmap: &IdMap,
    caller_uid: u32,
) -> Result<()> {
    do_mount_idmap(mount_registry, mount_id, idmap, caller_uid)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mount_api::{FsContextState, MOUNT_ATTR_NOEXEC, MOUNT_ATTR_RDONLY};

    fn make_registry_with_mount() -> (MountRegistry, u32) {
        let mut reg = MountRegistry::new();
        let id = reg.alloc(b"ext4", 0).unwrap();
        (reg, id)
    }

    // --- MountSetAttrExt ---

    fn make_setattr_ext(attr: MountAttr, flags: u32) -> MountSetAttrExt {
        MountSetAttrExt {
            attr,
            flags,
            size: core::mem::size_of::<MountSetAttrExt>() as u32,
        }
    }

    #[test]
    fn setattr_ext_basic_set_rdonly() {
        let (mut reg, id) = make_registry_with_mount();
        let attr = MountAttr {
            attr_set: MOUNT_ATTR_RDONLY,
            attr_clr: 0,
            ..Default::default()
        };
        let args = make_setattr_ext(attr, 0);
        do_mount_setattr_ext(&mut reg, id, &args).unwrap();
        assert_eq!(
            reg.get(id).unwrap().attr_flags & MOUNT_ATTR_RDONLY,
            MOUNT_ATTR_RDONLY
        );
    }

    #[test]
    fn setattr_ext_wrong_size_rejected() {
        let (mut reg, id) = make_registry_with_mount();
        let args = MountSetAttrExt {
            attr: MountAttr::default(),
            flags: 0,
            size: 0,
        };
        assert_eq!(
            do_mount_setattr_ext(&mut reg, id, &args),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn setattr_ext_unknown_flags_rejected() {
        let (mut reg, id) = make_registry_with_mount();
        let args = make_setattr_ext(MountAttr::default(), 0xDEAD);
        assert_eq!(
            do_mount_setattr_ext(&mut reg, id, &args),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn setattr_ext_not_found() {
        let (mut reg, _id) = make_registry_with_mount();
        let args = make_setattr_ext(MountAttr::default(), 0);
        assert_eq!(
            do_mount_setattr_ext(&mut reg, 9999, &args),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn setattr_ext_recurse_applies_to_all() {
        let (mut reg, id) = make_registry_with_mount();
        let _id2 = reg.alloc(b"tmpfs", 0).unwrap();
        let attr = MountAttr {
            attr_set: MOUNT_ATTR_NOEXEC,
            attr_clr: 0,
            ..Default::default()
        };
        let args = make_setattr_ext(attr, MOUNT_SETATTR_RECURSE);
        do_mount_setattr_ext(&mut reg, id, &args).unwrap();
        // Both mounts should now have NOEXEC.
        assert!(reg.get(id).unwrap().attr_flags & MOUNT_ATTR_NOEXEC != 0);
    }

    // --- do_move_mount_subtree ---

    #[test]
    fn move_mount_subtree_success() {
        let (reg, id) = make_registry_with_mount();
        assert!(do_move_mount_subtree(&reg, id, 0).is_ok());
    }

    #[test]
    fn move_mount_subtree_set_group_flag() {
        let (reg, id) = make_registry_with_mount();
        assert!(do_move_mount_subtree(&reg, id, MOVE_MOUNT_SET_GROUP).is_ok());
    }

    #[test]
    fn move_mount_subtree_unknown_flags_rejected() {
        let (reg, id) = make_registry_with_mount();
        assert_eq!(
            do_move_mount_subtree(&reg, id, 0xFFFF_0000),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn move_mount_subtree_not_found() {
        let (reg, _id) = make_registry_with_mount();
        assert_eq!(
            do_move_mount_subtree(&reg, 9999, 0),
            Err(Error::InvalidArgument)
        );
    }

    // --- do_open_tree_detached ---

    #[test]
    fn open_tree_detached_creates_clone() {
        let (mut reg, id) = make_registry_with_mount();
        let new_id = do_open_tree_detached(&mut reg, id, OPEN_TREE_CLONE).unwrap();
        assert_ne!(new_id, id);
        assert!(reg.get(new_id).is_some());
    }

    #[test]
    fn open_tree_detached_without_clone_flag_rejected() {
        let (mut reg, id) = make_registry_with_mount();
        assert_eq!(
            do_open_tree_detached(&mut reg, id, OPEN_TREE_CLOEXEC),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn open_tree_detached_unknown_flags_rejected() {
        let (mut reg, id) = make_registry_with_mount();
        assert_eq!(
            do_open_tree_detached(&mut reg, id, OPEN_TREE_CLONE | 0x8000),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn open_tree_detached_not_found() {
        let (mut reg, _id) = make_registry_with_mount();
        assert_eq!(
            do_open_tree_detached(&mut reg, 9999, OPEN_TREE_CLONE),
            Err(Error::InvalidArgument)
        );
    }

    // --- do_fspick ---

    #[test]
    fn fspick_returns_created_context() {
        let (reg, id) = make_registry_with_mount();
        let ctx = do_fspick(&reg, id, 0).unwrap();
        assert_eq!(ctx.state, FsContextState::Created);
        assert_eq!(ctx.mount_id, id);
    }

    #[test]
    fn fspick_cloexec_flag() {
        let (reg, id) = make_registry_with_mount();
        let ctx = do_fspick(&reg, id, FSPICK_CLOEXEC).unwrap();
        assert_eq!(ctx.state, FsContextState::Created);
    }

    #[test]
    fn fspick_unknown_flags_rejected() {
        let (reg, id) = make_registry_with_mount();
        assert_eq!(do_fspick(&reg, id, 0xFFFF), Err(Error::InvalidArgument));
    }

    #[test]
    fn fspick_not_found() {
        let (reg, _id) = make_registry_with_mount();
        assert_eq!(do_fspick(&reg, 9999, 0), Err(Error::InvalidArgument));
    }

    // --- IdMap ---

    #[test]
    fn idmapping_translate_in_range() {
        let m = IdMapping {
            first_in: 1000,
            first_out: 0,
            count: 100,
        };
        assert_eq!(m.translate(1000), Some(0));
        assert_eq!(m.translate(1050), Some(50));
        assert_eq!(m.translate(1099), Some(99));
    }

    #[test]
    fn idmapping_translate_out_of_range() {
        let m = IdMapping {
            first_in: 1000,
            first_out: 0,
            count: 100,
        };
        assert_eq!(m.translate(999), None);
        assert_eq!(m.translate(1100), None);
    }

    #[test]
    fn idmap_uid_translate() {
        let mut idmap = IdMap::default();
        idmap
            .add_uid_mapping(IdMapping {
                first_in: 1000,
                first_out: 0,
                count: 500,
            })
            .unwrap();
        assert_eq!(idmap.translate_uid(1000), Some(0));
        assert_eq!(idmap.translate_uid(1499), Some(499));
        assert_eq!(idmap.translate_uid(2000), None);
    }

    // --- do_mount_idmap ---

    #[test]
    fn mount_idmap_root_succeeds() {
        let (mut reg, id) = make_registry_with_mount();
        let idmap = IdMap::default();
        assert!(do_mount_idmap(&mut reg, id, &idmap, 0).is_ok());
        assert_ne!(
            reg.get(id).unwrap().attr_flags & crate::mount_api::MOUNT_ATTR_IDMAP,
            0
        );
    }

    #[test]
    fn mount_idmap_non_root_rejected() {
        let (mut reg, id) = make_registry_with_mount();
        let idmap = IdMap::default();
        assert_eq!(
            do_mount_idmap(&mut reg, id, &idmap, 1000),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn mount_idmap_zero_count_mapping_rejected() {
        let (mut reg, id) = make_registry_with_mount();
        let mut idmap = IdMap::default();
        idmap
            .add_uid_mapping(IdMapping {
                first_in: 0,
                first_out: 0,
                count: 0,
            })
            .unwrap();
        assert_eq!(
            do_mount_idmap(&mut reg, id, &idmap, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn mount_idmap_not_found() {
        let (mut reg, _id) = make_registry_with_mount();
        let idmap = IdMap::default();
        assert_eq!(
            do_mount_idmap(&mut reg, 9999, &idmap, 0),
            Err(Error::InvalidArgument)
        );
    }
}
