// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! tmpfs POSIX ACL support.
//!
//! Implements POSIX.1e Access Control Lists for tmpfs:
//! - [`AclTag`] — entry tag (USER_OBJ, USER, GROUP_OBJ, GROUP, MASK, OTHER)
//! - [`TmpfsAclEntry`] — single ACL entry (tag, perm bits, optional qualifier)
//! - [`TmpfsAcl`] — a complete access or default ACL (up to 32 entries)
//! - [`tmpfs_get_acl`] / [`tmpfs_set_acl`] — retrieve and store an ACL
//! - [`acl_permission_check`] — evaluate read/write/execute access
//! - Default ACL inheritance: child inherits parent's default ACL on creation
//! - [`acl_to_mode`] / [`mode_to_acl`] — synchronise ACL with UNIX mode bits
//!
//! # POSIX ACL Semantics
//!
//! An ACL consists of ACE (Access Control Entries). The minimal ACL is
//! equivalent to the UNIX permission bits (`owner/group/others`). Extended
//! ACLs add named-user and named-group entries plus a MASK entry that
//! effectively caps named-user/named-group/GROUP_OBJ permissions.
//!
//! # References
//! - Linux `include/linux/posix_acl.h`, `mm/shmem.c`
//! - POSIX.1-2024 §§ 4.4 (File Access Permissions)

extern crate alloc;
use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum ACL entries per inode.
pub const ACL_MAX_ENTRIES: usize = 32;

// ---------------------------------------------------------------------------
// AclTag
// ---------------------------------------------------------------------------

/// POSIX ACL entry tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AclTag {
    /// Owning user permissions.
    UserObj = 0x0001,
    /// Named user permissions.
    User = 0x0002,
    /// Owning group permissions.
    GroupObj = 0x0004,
    /// Named group permissions.
    Group = 0x0008,
    /// Effective rights mask.
    Mask = 0x0010,
    /// Other (world) permissions.
    Other = 0x0020,
}

// ---------------------------------------------------------------------------
// Permission bits
// ---------------------------------------------------------------------------

/// Read permission bit.
pub const ACL_READ: u8 = 0x04;
/// Write permission bit.
pub const ACL_WRITE: u8 = 0x02;
/// Execute permission bit.
pub const ACL_EXECUTE: u8 = 0x01;

// ---------------------------------------------------------------------------
// TmpfsAclEntry
// ---------------------------------------------------------------------------

/// A single POSIX ACL entry.
#[derive(Debug, Clone, Copy)]
pub struct TmpfsAclEntry {
    /// Entry tag (type).
    pub tag: AclTag,
    /// Permission bits (combination of ACL_READ, ACL_WRITE, ACL_EXECUTE).
    pub perm: u8,
    /// Qualifier: UID for User entries, GID for Group entries, 0 otherwise.
    pub qualifier: u32,
}

impl TmpfsAclEntry {
    /// Create a new ACL entry.
    pub fn new(tag: AclTag, perm: u8, qualifier: u32) -> Self {
        Self {
            tag,
            perm: perm & 0x07,
            qualifier,
        }
    }
}

// ---------------------------------------------------------------------------
// TmpfsAcl
// ---------------------------------------------------------------------------

/// A complete POSIX ACL (access or default).
#[derive(Debug, Clone)]
pub struct TmpfsAcl {
    entries: [Option<TmpfsAclEntry>; ACL_MAX_ENTRIES],
    count: usize,
}

impl TmpfsAcl {
    /// Create an empty ACL.
    pub fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
            count: 0,
        }
    }

    /// Build a minimal ACL equivalent to UNIX mode bits.
    ///
    /// `mode` is the 9 permission bits (rwxrwxrwx).
    pub fn from_mode(mode: u16) -> Self {
        let mut acl = Self::new();
        let owner_perm = ((mode >> 6) & 7) as u8;
        let group_perm = ((mode >> 3) & 7) as u8;
        let other_perm = (mode & 7) as u8;
        acl.add_entry(TmpfsAclEntry::new(AclTag::UserObj, owner_perm, 0))
            .ok();
        acl.add_entry(TmpfsAclEntry::new(AclTag::GroupObj, group_perm, 0))
            .ok();
        acl.add_entry(TmpfsAclEntry::new(AclTag::Other, other_perm, 0))
            .ok();
        acl
    }

    /// Add an entry to the ACL.
    ///
    /// Replaces an existing entry with the same tag + qualifier.
    pub fn add_entry(&mut self, entry: TmpfsAclEntry) -> Result<()> {
        for slot in self.entries[..self.count].iter_mut().flatten() {
            if slot.tag == entry.tag && slot.qualifier == entry.qualifier {
                *slot = entry;
                return Ok(());
            }
        }
        if self.count >= ACL_MAX_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = Some(entry);
        self.count += 1;
        Ok(())
    }

    /// Remove an entry by tag + qualifier.
    pub fn remove_entry(&mut self, tag: AclTag, qualifier: u32) -> bool {
        for i in 0..self.count {
            if let Some(e) = &self.entries[i] {
                if e.tag == tag && e.qualifier == qualifier {
                    if i < self.count - 1 {
                        self.entries.swap(i, self.count - 1);
                    }
                    self.entries[self.count - 1] = None;
                    self.count -= 1;
                    return true;
                }
            }
        }
        false
    }

    /// Find the effective MASK permission, or 0x07 if no MASK entry exists.
    fn mask_perm(&self) -> u8 {
        for slot in self.entries[..self.count].iter().flatten() {
            if slot.tag == AclTag::Mask {
                return slot.perm;
            }
        }
        0x07 // no mask = all bits allowed
    }

    /// Return true if this is a minimal ACL (only USER_OBJ, GROUP_OBJ, OTHER).
    pub fn is_minimal(&self) -> bool {
        self.count <= 3
            && self.entries[..self.count].iter().flatten().all(|e| {
                e.tag == AclTag::UserObj || e.tag == AclTag::GroupObj || e.tag == AclTag::Other
            })
    }

    /// Return all entries as a Vec.
    pub fn entries_vec(&self) -> Vec<TmpfsAclEntry> {
        self.entries[..self.count]
            .iter()
            .flatten()
            .copied()
            .collect()
    }
}

impl Default for TmpfsAcl {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Inode ACL store
// ---------------------------------------------------------------------------

/// Maximum number of tmpfs inodes tracked by the ACL store.
const ACL_STORE_SIZE: usize = 512;

/// Per-inode ACL storage.
pub struct TmpfsInodeAcl {
    /// Inode number.
    pub ino: u64,
    /// Access ACL.
    pub access_acl: Option<TmpfsAcl>,
    /// Default ACL (directories only).
    pub default_acl: Option<TmpfsAcl>,
}

/// ACL store for all tmpfs inodes.
pub struct TmpfsAclStore {
    entries: [Option<TmpfsInodeAcl>; ACL_STORE_SIZE],
    count: usize,
}

impl TmpfsAclStore {
    /// Create an empty ACL store.
    pub fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
            count: 0,
        }
    }

    fn find_idx(&self, ino: u64) -> Option<usize> {
        for (i, slot) in self.entries[..self.count].iter().enumerate() {
            if let Some(e) = slot {
                if e.ino == ino {
                    return Some(i);
                }
            }
        }
        None
    }

    fn get_or_create(&mut self, ino: u64) -> Result<usize> {
        if let Some(idx) = self.find_idx(ino) {
            return Ok(idx);
        }
        if self.count >= ACL_STORE_SIZE {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.entries[idx] = Some(TmpfsInodeAcl {
            ino,
            access_acl: None,
            default_acl: None,
        });
        self.count += 1;
        Ok(idx)
    }
}

impl Default for TmpfsAclStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// tmpfs_get_acl / tmpfs_set_acl
// ---------------------------------------------------------------------------

/// Get the access ACL for an inode.
///
/// Returns `None` if no ACL has been set (use UNIX mode bits instead).
pub fn tmpfs_get_acl(store: &TmpfsAclStore, ino: u64) -> Option<&TmpfsAcl> {
    let idx = store.find_idx(ino)?;
    store.entries[idx].as_ref()?.access_acl.as_ref()
}

/// Set the access ACL for an inode.
pub fn tmpfs_set_acl(store: &mut TmpfsAclStore, ino: u64, acl: TmpfsAcl) -> Result<()> {
    let idx = store.get_or_create(ino)?;
    if let Some(e) = store.entries[idx].as_mut() {
        e.access_acl = Some(acl);
    }
    Ok(())
}

/// Get the default ACL for a directory inode.
pub fn tmpfs_get_default_acl(store: &TmpfsAclStore, ino: u64) -> Option<&TmpfsAcl> {
    let idx = store.find_idx(ino)?;
    store.entries[idx].as_ref()?.default_acl.as_ref()
}

/// Set the default ACL for a directory inode.
pub fn tmpfs_set_default_acl(store: &mut TmpfsAclStore, ino: u64, acl: TmpfsAcl) -> Result<()> {
    let idx = store.get_or_create(ino)?;
    if let Some(e) = store.entries[idx].as_mut() {
        e.default_acl = Some(acl);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// acl_permission_check
// ---------------------------------------------------------------------------

/// Check whether (`uid`, `gid`) may perform `requested` operations
/// (`ACL_READ | ACL_WRITE | ACL_EXECUTE`) on a file with the given ACL.
///
/// Returns `Ok(())` on success, `Err(PermissionDenied)` on failure.
pub fn acl_permission_check(
    acl: &TmpfsAcl,
    file_uid: u32,
    file_gid: u32,
    caller_uid: u32,
    caller_gid: u32,
    requested: u8,
) -> Result<()> {
    let mask = acl.mask_perm();

    // Root bypasses permission checks.
    if caller_uid == 0 {
        return Ok(());
    }

    // Walk entries in POSIX order: USER_OBJ → USER → GROUP_OBJ/GROUP → OTHER.
    for slot in acl.entries[..acl.count].iter().flatten() {
        match slot.tag {
            AclTag::UserObj if caller_uid == file_uid => {
                if slot.perm & requested == requested {
                    return Ok(());
                }
                return Err(Error::PermissionDenied);
            }
            AclTag::User if caller_uid == slot.qualifier => {
                // Named-user entry is masked.
                let effective = slot.perm & mask;
                if effective & requested == requested {
                    return Ok(());
                }
                return Err(Error::PermissionDenied);
            }
            _ => {}
        }
    }
    // Group-class check.
    let mut group_match = false;
    for slot in acl.entries[..acl.count].iter().flatten() {
        match slot.tag {
            AclTag::GroupObj if caller_gid == file_gid => {
                group_match = true;
                if (slot.perm & mask) & requested == requested {
                    return Ok(());
                }
            }
            AclTag::Group if caller_gid == slot.qualifier => {
                group_match = true;
                if (slot.perm & mask) & requested == requested {
                    return Ok(());
                }
            }
            _ => {}
        }
    }
    if group_match {
        return Err(Error::PermissionDenied);
    }
    // Other.
    for slot in acl.entries[..acl.count].iter().flatten() {
        if slot.tag == AclTag::Other {
            if slot.perm & requested == requested {
                return Ok(());
            }
            return Err(Error::PermissionDenied);
        }
    }
    Err(Error::PermissionDenied)
}

// ---------------------------------------------------------------------------
// Default ACL inheritance
// ---------------------------------------------------------------------------

/// Inherit the parent directory's default ACL for a new child inode.
///
/// If the parent has a default ACL, the child's access ACL is initialised
/// from it. Returns `None` if there is no default ACL to inherit.
pub fn inherit_default_acl(
    store: &mut TmpfsAclStore,
    parent_ino: u64,
    child_ino: u64,
) -> Result<bool> {
    let default_acl = {
        let idx = store.find_idx(parent_ino);
        match idx {
            None => None,
            Some(i) => store.entries[i]
                .as_ref()
                .and_then(|e| e.default_acl.clone()),
        }
    };
    if let Some(acl) = default_acl {
        tmpfs_set_acl(store, child_ino, acl)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

// ---------------------------------------------------------------------------
// acl_to_mode / mode_to_acl
// ---------------------------------------------------------------------------

/// Derive the UNIX mode permission bits from an ACL.
///
/// Returns the 9 permission bits (rwxrwxrwx) derived from the ACL's
/// USER_OBJ, GROUP_OBJ (masked), and OTHER entries.
pub fn acl_to_mode(acl: &TmpfsAcl) -> u16 {
    let mask = acl.mask_perm();
    let mut owner = 0u8;
    let mut group = 0u8;
    let mut other = 0u8;

    for slot in acl.entries[..acl.count].iter().flatten() {
        match slot.tag {
            AclTag::UserObj => owner = slot.perm,
            AclTag::GroupObj => group = slot.perm & mask,
            AclTag::Mask => {} // handled above
            AclTag::Other => other = slot.perm,
            _ => {}
        }
    }
    (owner as u16) << 6 | (group as u16) << 3 | other as u16
}

/// Build a minimal ACL from UNIX mode bits.
///
/// Equivalent to `TmpfsAcl::from_mode`.
pub fn mode_to_acl(mode: u16) -> TmpfsAcl {
    TmpfsAcl::from_mode(mode)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_check_owner() {
        let acl = TmpfsAcl::from_mode(0o644);
        // Owner: read+write OK.
        acl_permission_check(&acl, 1000, 1000, 1000, 1000, ACL_READ | ACL_WRITE).unwrap();
        // Owner: execute denied.
        assert!(acl_permission_check(&acl, 1000, 1000, 1000, 1000, ACL_EXECUTE).is_err());
    }

    #[test]
    fn test_acl_to_mode() {
        let acl = TmpfsAcl::from_mode(0o755);
        let mode = acl_to_mode(&acl);
        assert_eq!(mode, 0o755);
    }

    #[test]
    fn test_set_get_acl() {
        let mut store = TmpfsAclStore::new();
        let acl = TmpfsAcl::from_mode(0o600);
        tmpfs_set_acl(&mut store, 42, acl).unwrap();
        let got = tmpfs_get_acl(&store, 42).unwrap();
        assert_eq!(acl_to_mode(got), 0o600);
    }
}
