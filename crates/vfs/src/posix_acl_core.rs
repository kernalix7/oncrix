// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX ACL core logic for the ONCRIX VFS.
//!
//! Implements the permission-checking and manipulation logic for POSIX.1e
//! Access Control Lists as defined in POSIX.1-2024. ACLs extend the
//! traditional Unix UGO (user/group/other) permission model to allow
//! per-user and per-group permission entries on filesystem objects.

use oncrix_lib::{Error, Result};

/// Maximum number of ACL entries per ACL (access or default).
pub const ACL_MAX_ENTRIES: usize = 32;

/// ACL tag types identifying the principal an entry applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AclTag {
    /// Permissions for the file owner.
    UserObj = 0x0001,
    /// Permissions for a named user.
    User = 0x0002,
    /// Permissions for the owning group.
    GroupObj = 0x0004,
    /// Permissions for a named group.
    Group = 0x0008,
    /// Mask entry (upper bound on named user/group permissions).
    Mask = 0x0010,
    /// Permissions for everyone else.
    Other = 0x0020,
}

impl AclTag {
    /// Parse an `AclTag` from its raw 16-bit value.
    pub fn from_u16(v: u16) -> Result<Self> {
        match v {
            0x0001 => Ok(Self::UserObj),
            0x0002 => Ok(Self::User),
            0x0004 => Ok(Self::GroupObj),
            0x0008 => Ok(Self::Group),
            0x0010 => Ok(Self::Mask),
            0x0020 => Ok(Self::Other),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// Permission bits within a single ACL entry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AclPerm {
    /// Read permission.
    pub read: bool,
    /// Write permission.
    pub write: bool,
    /// Execute permission.
    pub execute: bool,
}

impl AclPerm {
    /// Construct from a 3-bit rwx mask (bits 2=r, 1=w, 0=x).
    pub const fn from_bits(bits: u8) -> Self {
        Self {
            read: bits & 0x04 != 0,
            write: bits & 0x02 != 0,
            execute: bits & 0x01 != 0,
        }
    }

    /// Encode as a 3-bit rwx mask.
    pub fn to_bits(&self) -> u8 {
        let mut b = 0u8;
        if self.read {
            b |= 0x04;
        }
        if self.write {
            b |= 0x02;
        }
        if self.execute {
            b |= 0x01;
        }
        b
    }

    /// Return the bitwise AND (intersection) of two permission sets.
    pub fn and(&self, other: &Self) -> Self {
        Self {
            read: self.read && other.read,
            write: self.write && other.write,
            execute: self.execute && other.execute,
        }
    }
}

/// A single ACL entry (tag + optional qualifier + permissions).
#[derive(Debug, Clone, Copy)]
pub struct AclEntry {
    /// Tag identifying the principal type.
    pub tag: AclTag,
    /// Qualifier: UID for `User` entries, GID for `Group` entries; 0 otherwise.
    pub qualifier: u32,
    /// Permissions granted by this entry.
    pub perm: AclPerm,
}

impl AclEntry {
    /// Construct a `UserObj` entry.
    pub const fn user_obj(perm: AclPerm) -> Self {
        Self {
            tag: AclTag::UserObj,
            qualifier: 0,
            perm,
        }
    }

    /// Construct a named `User` entry.
    pub const fn user(uid: u32, perm: AclPerm) -> Self {
        Self {
            tag: AclTag::User,
            qualifier: uid,
            perm,
        }
    }

    /// Construct a `GroupObj` entry.
    pub const fn group_obj(perm: AclPerm) -> Self {
        Self {
            tag: AclTag::GroupObj,
            qualifier: 0,
            perm,
        }
    }

    /// Construct a named `Group` entry.
    pub const fn group(gid: u32, perm: AclPerm) -> Self {
        Self {
            tag: AclTag::Group,
            qualifier: gid,
            perm,
        }
    }

    /// Construct a `Mask` entry.
    pub const fn mask(perm: AclPerm) -> Self {
        Self {
            tag: AclTag::Mask,
            qualifier: 0,
            perm,
        }
    }

    /// Construct an `Other` entry.
    pub const fn other(perm: AclPerm) -> Self {
        Self {
            tag: AclTag::Other,
            qualifier: 0,
            perm,
        }
    }
}

impl Default for AclEntry {
    fn default() -> Self {
        Self::other(AclPerm::default())
    }
}

/// A complete POSIX ACL — a list of up to `ACL_MAX_ENTRIES` entries.
pub struct PosixAcl {
    entries: [AclEntry; ACL_MAX_ENTRIES],
    count: usize,
}

impl PosixAcl {
    /// Create an empty ACL.
    pub const fn new() -> Self {
        Self {
            entries: [AclEntry {
                tag: AclTag::Other,
                qualifier: 0,
                perm: AclPerm {
                    read: false,
                    write: false,
                    execute: false,
                },
            }; ACL_MAX_ENTRIES],
            count: 0,
        }
    }

    /// Add an entry to the ACL. Returns `OutOfMemory` if full.
    pub fn add(&mut self, entry: AclEntry) -> Result<()> {
        if self.count >= ACL_MAX_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = entry;
        self.count += 1;
        Ok(())
    }

    /// Check whether a process with `uid`/`gid` is granted `requested` permissions.
    ///
    /// Implements the POSIX ACL permission algorithm from POSIX.1-2024.
    ///
    /// `owner_uid` and `owner_gid` are the file's owning UID and GID.
    pub fn check(
        &self,
        uid: u32,
        gid: u32,
        owner_uid: u32,
        owner_gid: u32,
        requested: AclPerm,
    ) -> Result<()> {
        // Find the mask entry (if any).
        let mask = self.find_mask();

        // Step 1: If caller is the file owner, use ACL_USER_OBJ.
        if uid == owner_uid {
            for i in 0..self.count {
                if self.entries[i].tag == AclTag::UserObj {
                    return check_perm(&self.entries[i].perm, &requested);
                }
            }
            return Err(Error::PermissionDenied);
        }

        // Step 2: Look for an ACL_USER entry matching the caller's UID.
        for i in 0..self.count {
            let e = &self.entries[i];
            if e.tag == AclTag::User && e.qualifier == uid {
                let effective = match mask {
                    Some(m) => e.perm.and(m),
                    None => e.perm,
                };
                return check_perm(&effective, &requested);
            }
        }

        // Step 3: Check ACL_GROUP_OBJ and ACL_GROUP entries.
        let mut group_match = false;
        for i in 0..self.count {
            let e = &self.entries[i];
            let is_group_match = (e.tag == AclTag::GroupObj && gid == owner_gid)
                || (e.tag == AclTag::Group && e.qualifier == gid);
            if is_group_match {
                group_match = true;
                let effective = match mask {
                    Some(m) => e.perm.and(m),
                    None => e.perm,
                };
                if check_perm(&effective, &requested).is_ok() {
                    return Ok(());
                }
            }
        }
        if group_match {
            return Err(Error::PermissionDenied);
        }

        // Step 4: Use ACL_OTHER.
        for i in 0..self.count {
            if self.entries[i].tag == AclTag::Other {
                return check_perm(&self.entries[i].perm, &requested);
            }
        }

        Err(Error::PermissionDenied)
    }

    /// Find the mask entry and return a reference to its permissions.
    fn find_mask(&self) -> Option<&AclPerm> {
        for i in 0..self.count {
            if self.entries[i].tag == AclTag::Mask {
                return Some(&self.entries[i].perm);
            }
        }
        None
    }

    /// Return the number of entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if the ACL has no entries.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return a slice of the entries.
    pub fn entries(&self) -> &[AclEntry] {
        &self.entries[..self.count]
    }
}

impl Default for PosixAcl {
    fn default() -> Self {
        Self::new()
    }
}

/// Check that all bits of `requested` are set in `granted`.
fn check_perm(granted: &AclPerm, requested: &AclPerm) -> Result<()> {
    if requested.read && !granted.read {
        return Err(Error::PermissionDenied);
    }
    if requested.write && !granted.write {
        return Err(Error::PermissionDenied);
    }
    if requested.execute && !granted.execute {
        return Err(Error::PermissionDenied);
    }
    Ok(())
}

/// Convert a standard Unix mode (9-bit rwxrwxrwx) to a minimal 3-entry ACL.
pub fn mode_to_acl(mode: u16) -> PosixAcl {
    let mut acl = PosixAcl::new();
    let _ = acl.add(AclEntry::user_obj(AclPerm::from_bits(
        ((mode >> 6) & 0x07) as u8,
    )));
    let _ = acl.add(AclEntry::group_obj(AclPerm::from_bits(
        ((mode >> 3) & 0x07) as u8,
    )));
    let _ = acl.add(AclEntry::other(AclPerm::from_bits((mode & 0x07) as u8)));
    acl
}

/// Convert a minimal 3-entry ACL back to a Unix mode word (owner/group/other bits only).
pub fn acl_to_mode(acl: &PosixAcl) -> u16 {
    let mut mode = 0u16;
    for e in acl.entries() {
        match e.tag {
            AclTag::UserObj => mode |= (e.perm.to_bits() as u16) << 6,
            AclTag::GroupObj => mode |= (e.perm.to_bits() as u16) << 3,
            AclTag::Other => mode |= e.perm.to_bits() as u16,
            _ => {}
        }
    }
    mode
}
