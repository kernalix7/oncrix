// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX Access Control Lists (ACLs).
//!
//! Implements POSIX.1e-style ACLs that extend the traditional Unix
//! owner/group/other permission model with fine-grained per-user
//! and per-group access control entries.
//!
//! # ACL evaluation algorithm
//!
//! Access checks follow the POSIX ACL algorithm:
//! 1. If the process owns the file → use `UserObj` entry.
//! 2. If a named `User` entry matches → intersect with `Mask`.
//! 3. If the file's owning group or a named `Group` entry
//!    matches → intersect with `Mask`.
//! 4. Otherwise → use the `Other` entry.
//!
//! # References
//!
//! - POSIX.1e draft 17 (withdrawn but widely implemented)
//! - Linux `acl(5)`, `setfacl(1)`, `getfacl(1)`

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Maximum number of ACL entries per inode.
pub const MAX_ACL_ENTRIES: usize = 32;

/// Maximum number of inodes tracked by the global ACL registry.
pub const MAX_ACL_INODES: usize = 256;

/// ACL permission bit: read.
pub const ACL_READ: u8 = 4;

/// ACL permission bit: write.
pub const ACL_WRITE: u8 = 2;

/// ACL permission bit: execute.
pub const ACL_EXECUTE: u8 = 1;

// ── AclTag ──────────────────────────────────────────────────────

/// Identifies the type of an ACL entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u16)]
pub enum AclTag {
    /// Owning user (corresponds to Unix owner bits).
    #[default]
    UserObj = 0x01,
    /// Named user entry.
    User = 0x02,
    /// Owning group (corresponds to Unix group bits).
    GroupObj = 0x04,
    /// Named group entry.
    Group = 0x08,
    /// Maximum permissions for User/Group entries.
    Mask = 0x10,
    /// Permissions for everyone else.
    Other = 0x20,
}

// ── AclPerm ─────────────────────────────────────────────────────

/// A set of ACL permission bits (read / write / execute).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AclPerm {
    /// Raw permission bits (combination of `ACL_READ`,
    /// `ACL_WRITE`, `ACL_EXECUTE`).
    bits: u8,
}

impl AclPerm {
    /// Creates a new permission set from individual flags.
    pub const fn new(read: bool, write: bool, execute: bool) -> Self {
        let mut bits = 0u8;
        if read {
            bits |= ACL_READ;
        }
        if write {
            bits |= ACL_WRITE;
        }
        if execute {
            bits |= ACL_EXECUTE;
        }
        Self { bits }
    }

    /// Returns `true` if the read bit is set.
    pub const fn read(&self) -> bool {
        self.bits & ACL_READ != 0
    }

    /// Returns `true` if the write bit is set.
    pub const fn write(&self) -> bool {
        self.bits & ACL_WRITE != 0
    }

    /// Returns `true` if the execute bit is set.
    pub const fn execute(&self) -> bool {
        self.bits & ACL_EXECUTE != 0
    }

    /// Constructs permissions from a 3-bit slice of a Unix mode
    /// value. The lowest 3 bits of `mode` are interpreted as
    /// `rwx`.
    pub const fn from_mode(mode: u16) -> Self {
        Self {
            bits: (mode & 0o7) as u8,
        }
    }

    /// Converts the permission set back to a 3-bit Unix mode
    /// value.
    pub const fn to_mode(&self) -> u16 {
        self.bits as u16
    }

    /// Returns the intersection (bitwise AND) of two permission
    /// sets.
    pub const fn intersect(&self, other: &AclPerm) -> AclPerm {
        AclPerm {
            bits: self.bits & other.bits,
        }
    }
}

// ── AclEntry ────────────────────────────────────────────────────

/// A single ACL entry associating a tag+qualifier with a
/// permission set.
#[derive(Debug, Clone, Copy)]
pub struct AclEntry {
    /// Entry type (user-obj, named user, group-obj, …).
    pub tag: AclTag,
    /// Granted permissions.
    pub perm: AclPerm,
    /// UID or GID — meaningful only for `User` and `Group` tags.
    pub qualifier: u32,
    /// Whether this entry is in use.
    pub active: bool,
}

impl Default for AclEntry {
    fn default() -> Self {
        Self {
            tag: AclTag::UserObj,
            perm: AclPerm::default(),
            qualifier: 0,
            active: false,
        }
    }
}

// ── Acl ─────────────────────────────────────────────────────────

/// Per-inode POSIX ACL.
#[derive(Debug, Clone)]
pub struct Acl {
    /// Fixed-size entry table.
    entries: [AclEntry; MAX_ACL_ENTRIES],
    /// Number of active entries.
    count: usize,
    /// Inode this ACL is attached to.
    inode: u64,
    /// `true` if this is a default (inheritable) ACL.
    _is_default: bool,
    /// Whether this ACL is active.
    active: bool,
}

impl Default for Acl {
    fn default() -> Self {
        Self {
            entries: [AclEntry::default(); MAX_ACL_ENTRIES],
            count: 0,
            inode: 0,
            _is_default: false,
            active: false,
        }
    }
}

impl Acl {
    /// Adds a new entry to the ACL.
    ///
    /// Returns `OutOfMemory` if the entry table is full, or
    /// `AlreadyExists` if an entry with the same tag and
    /// qualifier already exists.
    pub fn add_entry(&mut self, tag: AclTag, perm: AclPerm, qualifier: u32) -> Result<()> {
        // Reject duplicates.
        for entry in &self.entries[..self.count] {
            if entry.active && entry.tag == tag && entry.qualifier == qualifier {
                return Err(Error::AlreadyExists);
            }
        }

        if self.count >= MAX_ACL_ENTRIES {
            return Err(Error::OutOfMemory);
        }

        self.entries[self.count] = AclEntry {
            tag,
            perm,
            qualifier,
            active: true,
        };
        self.count += 1;
        Ok(())
    }

    /// Removes an entry identified by `tag` and `qualifier`.
    ///
    /// Returns `NotFound` if no matching entry exists.
    pub fn remove_entry(&mut self, tag: AclTag, qualifier: u32) -> Result<()> {
        for i in 0..self.count {
            if self.entries[i].active
                && self.entries[i].tag == tag
                && self.entries[i].qualifier == qualifier
            {
                // Swap-remove to keep entries compact.
                self.entries[i] = self.entries[self.count - 1];
                self.entries[self.count - 1] = AclEntry::default();
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Looks up an entry by `tag` and `qualifier`.
    pub fn get_entry(&self, tag: AclTag, qualifier: u32) -> Option<&AclEntry> {
        self.entries[..self.count]
            .iter()
            .find(|e| e.active && e.tag == tag && e.qualifier == qualifier)
    }

    /// Checks whether the given user has the requested access
    /// according to the POSIX ACL algorithm.
    ///
    /// Returns `Ok(())` on success or `PermissionDenied` if
    /// access is denied.
    pub fn check_access(&self, uid: u32, gid: u32, want: AclPerm) -> Result<()> {
        // Step 1: UserObj — if the caller owns the file the
        // UserObj entry decides (no Mask applied).
        if let Some(e) = self.find_tag(AclTag::UserObj) {
            if e.qualifier == uid || uid == 0 {
                return Self::check_bits(e.perm, want);
            }
        }

        let mask = self.find_tag(AclTag::Mask).map(|m| m.perm);

        // Step 2: Named User entries (intersected with Mask).
        for entry in &self.entries[..self.count] {
            if entry.active && entry.tag == AclTag::User && entry.qualifier == uid {
                let effective = match mask {
                    Some(m) => entry.perm.intersect(&m),
                    None => entry.perm,
                };
                return Self::check_bits(effective, want);
            }
        }

        // Step 3: GroupObj and named Group entries. Any matching
        // group grants access (all intersected with Mask).
        let mut group_matched = false;

        if let Some(e) = self.find_tag(AclTag::GroupObj) {
            if e.qualifier == gid {
                let effective = match mask {
                    Some(m) => e.perm.intersect(&m),
                    None => e.perm,
                };
                if Self::check_bits(effective, want).is_ok() {
                    return Ok(());
                }
                group_matched = true;
            }
        }

        for entry in &self.entries[..self.count] {
            if entry.active && entry.tag == AclTag::Group && entry.qualifier == gid {
                let effective = match mask {
                    Some(m) => entry.perm.intersect(&m),
                    None => entry.perm,
                };
                if Self::check_bits(effective, want).is_ok() {
                    return Ok(());
                }
                group_matched = true;
            }
        }

        if group_matched {
            return Err(Error::PermissionDenied);
        }

        // Step 4: Other.
        if let Some(e) = self.find_tag(AclTag::Other) {
            return Self::check_bits(e.perm, want);
        }

        Err(Error::PermissionDenied)
    }

    /// Validates the ACL against POSIX structural rules.
    ///
    /// A valid ACL must contain exactly one `UserObj`, one
    /// `GroupObj`, and one `Other` entry. If any named `User`
    /// or `Group` entries exist a `Mask` entry is required.
    pub fn is_valid(&self) -> bool {
        let mut user_obj = 0u32;
        let mut group_obj = 0u32;
        let mut other = 0u32;
        let mut mask = 0u32;
        let mut has_named = false;

        for entry in &self.entries[..self.count] {
            if !entry.active {
                continue;
            }
            match entry.tag {
                AclTag::UserObj => user_obj += 1,
                AclTag::GroupObj => group_obj += 1,
                AclTag::Other => other += 1,
                AclTag::Mask => mask += 1,
                AclTag::User | AclTag::Group => {
                    has_named = true;
                }
            }
        }

        if user_obj != 1 || group_obj != 1 || other != 1 {
            return false;
        }
        if has_named && mask == 0 {
            return false;
        }
        true
    }

    /// Creates a minimal (three-entry) ACL from traditional Unix
    /// permission bits.
    ///
    /// `mode` is the full 12-bit mode value; only the lower 9
    /// bits (owner/group/other rwx) are used.
    pub fn from_mode(mode: u16) -> Self {
        let mut entries = [AclEntry::default(); MAX_ACL_ENTRIES];

        // Owner bits (bits 8–6).
        entries[0] = AclEntry {
            tag: AclTag::UserObj,
            perm: AclPerm::from_mode(mode >> 6),
            qualifier: 0,
            active: true,
        };
        // Group bits (bits 5–3).
        entries[1] = AclEntry {
            tag: AclTag::GroupObj,
            perm: AclPerm::from_mode(mode >> 3),
            qualifier: 0,
            active: true,
        };
        // Other bits (bits 2–0).
        entries[2] = AclEntry {
            tag: AclTag::Other,
            perm: AclPerm::from_mode(mode),
            qualifier: 0,
            active: true,
        };

        Self {
            entries,
            count: 3,
            inode: 0,
            _is_default: false,
            active: true,
        }
    }

    /// Converts the ACL back to a 9-bit Unix permission mode.
    ///
    /// Uses the `UserObj` entry for owner bits, the `Mask` entry
    /// (or `GroupObj` if no mask) for group bits, and the `Other`
    /// entry for other bits.
    pub fn to_mode(&self) -> u16 {
        let owner = self
            .find_tag(AclTag::UserObj)
            .map_or(0, |e| e.perm.to_mode());
        let group = self
            .find_tag(AclTag::Mask)
            .or_else(|| self.find_tag(AclTag::GroupObj))
            .map_or(0, |e| e.perm.to_mode());
        let other = self.find_tag(AclTag::Other).map_or(0, |e| e.perm.to_mode());

        (owner << 6) | (group << 3) | other
    }

    /// Returns the number of active entries.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if there are no active entries.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    // ── Private helpers ─────────────────────────────────────────

    /// Finds the first active entry with the given tag.
    fn find_tag(&self, tag: AclTag) -> Option<&AclEntry> {
        self.entries[..self.count]
            .iter()
            .find(|e| e.active && e.tag == tag)
    }

    /// Returns `Ok` if `have` is a superset of `want`.
    fn check_bits(have: AclPerm, want: AclPerm) -> Result<()> {
        if have.bits & want.bits == want.bits {
            Ok(())
        } else {
            Err(Error::PermissionDenied)
        }
    }
}

// ── AclRegistry ─────────────────────────────────────────────────

/// Global registry mapping inodes to their ACLs.
pub struct AclRegistry {
    /// Fixed-size ACL table.
    acls: [Acl; MAX_ACL_INODES],
    /// Number of registered ACLs.
    count: usize,
}

impl Default for AclRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AclRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        const DEFAULT_ENTRY: AclEntry = AclEntry {
            tag: AclTag::UserObj,
            perm: AclPerm { bits: 0 },
            qualifier: 0,
            active: false,
        };
        const DEFAULT_ACL: Acl = Acl {
            entries: [DEFAULT_ENTRY; MAX_ACL_ENTRIES],
            count: 0,
            inode: 0,
            _is_default: false,
            active: false,
        };
        Self {
            acls: [DEFAULT_ACL; MAX_ACL_INODES],
            count: 0,
        }
    }

    /// Associates an ACL with the given inode.
    ///
    /// If an ACL for `inode` already exists it is replaced.
    /// Returns `OutOfMemory` when the registry is full.
    pub fn set_acl(&mut self, inode: u64, acl: &Acl) -> Result<()> {
        // Update in place if already tracked.
        for slot in &mut self.acls[..self.count] {
            if slot.active && slot.inode == inode {
                *slot = acl.clone();
                slot.inode = inode;
                slot.active = true;
                return Ok(());
            }
        }

        if self.count >= MAX_ACL_INODES {
            return Err(Error::OutOfMemory);
        }

        let mut entry = acl.clone();
        entry.inode = inode;
        entry.active = true;
        self.acls[self.count] = entry;
        self.count += 1;
        Ok(())
    }

    /// Returns the ACL for `inode`, if one is registered.
    pub fn get_acl(&self, inode: u64) -> Option<&Acl> {
        self.acls[..self.count]
            .iter()
            .find(|a| a.active && a.inode == inode)
    }

    /// Removes the ACL for `inode`.
    ///
    /// Returns `NotFound` if no ACL is registered for the inode.
    pub fn remove_acl(&mut self, inode: u64) -> Result<()> {
        for i in 0..self.count {
            if self.acls[i].active && self.acls[i].inode == inode {
                self.acls[i] = self.acls[self.count - 1].clone();
                self.acls[self.count - 1] = Self::new().acls[0].clone();
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Checks whether `uid`/`gid` has the requested permissions
    /// on `inode`.
    ///
    /// Returns `NotFound` if no ACL is registered for the inode.
    pub fn check_permission(&self, inode: u64, uid: u32, gid: u32, want: AclPerm) -> Result<()> {
        match self.get_acl(inode) {
            Some(acl) => acl.check_access(uid, gid, want),
            None => Err(Error::NotFound),
        }
    }

    /// Returns the number of registered ACLs.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no ACLs are registered.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}
