// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel credential structures and management.
//!
//! Manages the security credentials associated with kernel tasks
//! including UIDs, GIDs, capabilities, security labels, and
//! keyrings. Credentials are immutable once committed — changes
//! require creating a new credential set and atomically swapping
//! it. This copy-on-write model ensures lock-free credential
//! reads in the common path.

use oncrix_lib::{Error, Result};

/// Maximum number of supplementary groups.
const MAX_GROUPS: usize = 32;

/// Maximum number of credential sets tracked.
const MAX_CREDS: usize = 1024;

/// Maximum number of capability bits.
const CAP_WORDS: usize = 2;

/// User identifier type.
pub type Uid = u32;

/// Group identifier type.
pub type Gid = u32;

/// Root UID.
const _ROOT_UID: Uid = 0;

/// Root GID.
const _ROOT_GID: Gid = 0;

/// Capability set (bitmask of capabilities).
#[derive(Clone, Copy)]
pub struct CapabilitySet {
    /// Capability bits.
    bits: [u64; CAP_WORDS],
}

impl CapabilitySet {
    /// Creates an empty capability set.
    pub const fn empty() -> Self {
        Self {
            bits: [0u64; CAP_WORDS],
        }
    }

    /// Creates a full capability set (all caps).
    pub const fn full() -> Self {
        Self {
            bits: [u64::MAX; CAP_WORDS],
        }
    }

    /// Checks if a capability is set.
    pub fn has_cap(&self, cap: u32) -> bool {
        let word = (cap / 64) as usize;
        let bit = cap % 64;
        if word >= CAP_WORDS {
            return false;
        }
        (self.bits[word] & (1u64 << bit)) != 0
    }

    /// Raises a capability.
    pub fn raise(&mut self, cap: u32) -> Result<()> {
        let word = (cap / 64) as usize;
        let bit = cap % 64;
        if word >= CAP_WORDS {
            return Err(Error::InvalidArgument);
        }
        self.bits[word] |= 1u64 << bit;
        Ok(())
    }

    /// Drops a capability.
    pub fn drop_cap(&mut self, cap: u32) -> Result<()> {
        let word = (cap / 64) as usize;
        let bit = cap % 64;
        if word >= CAP_WORDS {
            return Err(Error::InvalidArgument);
        }
        self.bits[word] &= !(1u64 << bit);
        Ok(())
    }

    /// Returns the intersection of two capability sets.
    pub fn intersect(&self, other: &Self) -> Self {
        let mut result = Self::empty();
        for i in 0..CAP_WORDS {
            result.bits[i] = self.bits[i] & other.bits[i];
        }
        result
    }

    /// Returns whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|w| *w == 0)
    }

    /// Returns whether this is a subset of another.
    pub fn is_subset_of(&self, other: &Self) -> bool {
        for i in 0..CAP_WORDS {
            if (self.bits[i] & !other.bits[i]) != 0 {
                return false;
            }
        }
        true
    }
}

impl Default for CapabilitySet {
    fn default() -> Self {
        Self::empty()
    }
}

/// Kernel credential set for a task.
#[derive(Clone, Copy)]
pub struct Credentials {
    /// Credential set identifier.
    id: u64,
    /// Real UID.
    uid: Uid,
    /// Effective UID.
    euid: Uid,
    /// Saved set-UID.
    suid: Uid,
    /// Filesystem UID.
    fsuid: Uid,
    /// Real GID.
    gid: Gid,
    /// Effective GID.
    egid: Gid,
    /// Saved set-GID.
    sgid: Gid,
    /// Filesystem GID.
    fsgid: Gid,
    /// Supplementary groups.
    groups: [Gid; MAX_GROUPS],
    /// Number of supplementary groups.
    group_count: u8,
    /// Permitted capabilities.
    cap_permitted: CapabilitySet,
    /// Effective capabilities.
    cap_effective: CapabilitySet,
    /// Inheritable capabilities.
    cap_inheritable: CapabilitySet,
    /// Bounding set.
    cap_bounding: CapabilitySet,
    /// Ambient capabilities.
    cap_ambient: CapabilitySet,
    /// Security label ID (LSM).
    security_label: u64,
    /// Whether this credential set is committed (immutable).
    committed: bool,
    /// Reference count (for copy-on-write).
    ref_count: u32,
}

impl Credentials {
    /// Creates a new credential set with root privileges.
    pub const fn new() -> Self {
        Self {
            id: 0,
            uid: 0,
            euid: 0,
            suid: 0,
            fsuid: 0,
            gid: 0,
            egid: 0,
            sgid: 0,
            fsgid: 0,
            groups: [0u32; MAX_GROUPS],
            group_count: 0,
            cap_permitted: CapabilitySet::empty(),
            cap_effective: CapabilitySet::empty(),
            cap_inheritable: CapabilitySet::empty(),
            cap_bounding: CapabilitySet::full(),
            cap_ambient: CapabilitySet::empty(),
            security_label: 0,
            committed: false,
            ref_count: 1,
        }
    }

    /// Creates credentials for a specific UID/GID.
    pub const fn for_user(uid: Uid, gid: Gid) -> Self {
        Self {
            id: 0,
            uid,
            euid: uid,
            suid: uid,
            fsuid: uid,
            gid,
            egid: gid,
            sgid: gid,
            fsgid: gid,
            groups: [0u32; MAX_GROUPS],
            group_count: 0,
            cap_permitted: CapabilitySet::empty(),
            cap_effective: CapabilitySet::empty(),
            cap_inheritable: CapabilitySet::empty(),
            cap_bounding: CapabilitySet::full(),
            cap_ambient: CapabilitySet::empty(),
            security_label: 0,
            committed: false,
            ref_count: 1,
        }
    }

    /// Returns the credential set ID.
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Returns the real UID.
    pub const fn uid(&self) -> Uid {
        self.uid
    }

    /// Returns the effective UID.
    pub const fn euid(&self) -> Uid {
        self.euid
    }

    /// Returns the real GID.
    pub const fn gid(&self) -> Gid {
        self.gid
    }

    /// Returns the effective GID.
    pub const fn egid(&self) -> Gid {
        self.egid
    }

    /// Returns whether this is a root credential.
    pub const fn is_root(&self) -> bool {
        self.euid == 0
    }

    /// Returns the permitted capability set.
    pub const fn cap_permitted(&self) -> &CapabilitySet {
        &self.cap_permitted
    }

    /// Returns the effective capability set.
    pub const fn cap_effective(&self) -> &CapabilitySet {
        &self.cap_effective
    }

    /// Returns whether this credential is committed.
    pub const fn is_committed(&self) -> bool {
        self.committed
    }

    /// Sets the UIDs (real, effective, saved).
    pub fn set_uids(&mut self, uid: Uid, euid: Uid, suid: Uid) -> Result<()> {
        if self.committed {
            return Err(Error::PermissionDenied);
        }
        self.uid = uid;
        self.euid = euid;
        self.suid = suid;
        self.fsuid = euid;
        Ok(())
    }

    /// Sets the GIDs (real, effective, saved).
    pub fn set_gids(&mut self, gid: Gid, egid: Gid, sgid: Gid) -> Result<()> {
        if self.committed {
            return Err(Error::PermissionDenied);
        }
        self.gid = gid;
        self.egid = egid;
        self.sgid = sgid;
        self.fsgid = egid;
        Ok(())
    }

    /// Adds a supplementary group.
    pub fn add_group(&mut self, group: Gid) -> Result<()> {
        if self.committed {
            return Err(Error::PermissionDenied);
        }
        if (self.group_count as usize) >= MAX_GROUPS {
            return Err(Error::OutOfMemory);
        }
        self.groups[self.group_count as usize] = group;
        self.group_count += 1;
        Ok(())
    }

    /// Checks if the credential includes a group.
    pub fn in_group(&self, group: Gid) -> bool {
        if self.egid == group {
            return true;
        }
        for i in 0..self.group_count as usize {
            if self.groups[i] == group {
                return true;
            }
        }
        false
    }

    /// Commits the credential set (makes it immutable).
    pub fn commit(&mut self) {
        self.committed = true;
    }

    /// Returns the number of supplementary groups.
    pub const fn group_count(&self) -> u8 {
        self.group_count
    }
}

impl Default for Credentials {
    fn default() -> Self {
        Self::new()
    }
}

/// Credential manager for the system.
pub struct CredentialManager {
    /// All credential sets.
    creds: [Credentials; MAX_CREDS],
    /// Number of credential sets.
    count: usize,
    /// Next credential ID.
    next_id: u64,
}

impl CredentialManager {
    /// Creates a new credential manager.
    pub const fn new() -> Self {
        Self {
            creds: [const { Credentials::new() }; MAX_CREDS],
            count: 0,
            next_id: 1,
        }
    }

    /// Creates a new credential set for a user.
    pub fn create_cred(&mut self, uid: Uid, gid: Gid) -> Result<u64> {
        if self.count >= MAX_CREDS {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_id;
        self.next_id += 1;
        self.creds[self.count] = Credentials::for_user(uid, gid);
        self.creds[self.count].id = id;
        self.count += 1;
        Ok(id)
    }

    /// Gets a credential set by ID.
    pub fn get_cred(&self, id: u64) -> Result<&Credentials> {
        self.creds[..self.count]
            .iter()
            .find(|c| c.id == id)
            .ok_or(Error::NotFound)
    }

    /// Gets a mutable credential set by ID.
    pub fn get_cred_mut(&mut self, id: u64) -> Result<&mut Credentials> {
        self.creds[..self.count]
            .iter_mut()
            .find(|c| c.id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns the number of credential sets.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for CredentialManager {
    fn default() -> Self {
        Self::new()
    }
}
