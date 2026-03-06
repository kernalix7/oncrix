// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Credential-based VFS access checking.
//!
//! Provides higher-level credential validation for VFS operations,
//! building on top of inode permission bits to implement full POSIX
//! access control semantics including capability checks.

use oncrix_lib::{Error, Result};

/// Linux capability numbers relevant to VFS operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Capability {
    /// Bypass file read/write/execute permission checks.
    DacOverride = 1,
    /// Bypass file read permission checks and directory read/execute checks.
    DacReadSearch = 2,
    /// Set file owner UID/GID.
    Chown = 3,
    /// Make arbitrary changes to file UIDs and GIDs.
    Setuid = 7,
    /// Set file capabilities.
    Setpcap = 8,
    /// Perform system administration operations.
    SysAdmin = 21,
    /// Use chroot.
    SysChroot = 18,
    /// Perform file locking beyond process limits.
    SysResource = 24,
}

/// A capability set as a bitmask (lower 32 capabilities).
#[derive(Debug, Clone, Copy, Default)]
pub struct CapSet(pub u64);

impl CapSet {
    /// Create an empty capability set (no capabilities).
    pub const fn empty() -> Self {
        CapSet(0)
    }

    /// Create a full capability set (all capabilities).
    pub const fn full() -> Self {
        CapSet(u64::MAX)
    }

    /// Check if a capability is present.
    pub fn has(self, cap: Capability) -> bool {
        self.0 & (1u64 << cap as u32) != 0
    }

    /// Add a capability.
    pub fn add(mut self, cap: Capability) -> Self {
        self.0 |= 1u64 << cap as u32;
        self
    }
}

/// Full credential set for a VFS operation.
#[derive(Debug, Clone, Copy)]
pub struct VfsCred {
    /// Real user ID.
    pub ruid: u32,
    /// Effective user ID.
    pub euid: u32,
    /// Saved set-user-ID.
    pub suid: u32,
    /// Real group ID.
    pub rgid: u32,
    /// Effective group ID.
    pub egid: u32,
    /// Effective capability set.
    pub caps: CapSet,
    /// User namespace ID (0 = initial namespace).
    pub userns: u32,
}

impl VfsCred {
    /// Create a root credential with all capabilities.
    pub const fn root() -> Self {
        VfsCred {
            ruid: 0,
            euid: 0,
            suid: 0,
            rgid: 0,
            egid: 0,
            caps: CapSet::full(),
            userns: 0,
        }
    }

    /// Create a credential for an unprivileged user.
    pub const fn user(uid: u32, gid: u32) -> Self {
        VfsCred {
            ruid: uid,
            euid: uid,
            suid: uid,
            rgid: gid,
            egid: gid,
            caps: CapSet::empty(),
            userns: 0,
        }
    }

    /// Check if the credential has a specific capability.
    pub fn capable(&self, cap: Capability) -> bool {
        self.caps.has(cap)
    }

    /// Check if the process is running as root (euid == 0).
    pub fn is_root(&self) -> bool {
        self.euid == 0
    }
}

/// Result of an access check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessResult {
    /// Access is explicitly granted.
    Granted,
    /// Access is denied.
    Denied,
}

/// Check if a credential may read a file owned by `owner_uid`/`owner_gid`.
pub fn check_read_access(
    cred: &VfsCred,
    owner_uid: u32,
    owner_gid: u32,
    mode: u16,
) -> AccessResult {
    if cred.capable(Capability::DacReadSearch) || cred.capable(Capability::DacOverride) {
        return AccessResult::Granted;
    }
    let bits = effective_bits(cred, owner_uid, owner_gid, mode);
    if bits & 4 != 0 {
        AccessResult::Granted
    } else {
        AccessResult::Denied
    }
}

/// Check if a credential may write a file owned by `owner_uid`/`owner_gid`.
pub fn check_write_access(
    cred: &VfsCred,
    owner_uid: u32,
    owner_gid: u32,
    mode: u16,
) -> AccessResult {
    if cred.capable(Capability::DacOverride) {
        return AccessResult::Granted;
    }
    let bits = effective_bits(cred, owner_uid, owner_gid, mode);
    if bits & 2 != 0 {
        AccessResult::Granted
    } else {
        AccessResult::Denied
    }
}

/// Check if a credential may execute a file.
pub fn check_exec_access(
    cred: &VfsCred,
    owner_uid: u32,
    owner_gid: u32,
    mode: u16,
) -> AccessResult {
    let (o, g, oth) = ((mode >> 6) & 7, (mode >> 3) & 7, mode & 7);
    let any_exec = (o | g | oth) & 1 != 0;
    if cred.capable(Capability::DacOverride) && any_exec {
        return AccessResult::Granted;
    }
    let bits = effective_bits(cred, owner_uid, owner_gid, mode);
    if bits & 1 != 0 {
        AccessResult::Granted
    } else {
        AccessResult::Denied
    }
}

/// Check if a credential may chown a file.
///
/// Only the owner (or root) may change ownership.
pub fn check_chown(cred: &VfsCred, file_uid: u32, new_uid: u32, new_gid: u32) -> Result<()> {
    if cred.capable(Capability::Chown) {
        return Ok(());
    }
    // Non-root: may only change gid to own gid; cannot change uid.
    if cred.euid != file_uid {
        return Err(Error::PermissionDenied);
    }
    if new_uid != file_uid {
        return Err(Error::PermissionDenied);
    }
    // Must own the new gid.
    if new_gid != cred.egid {
        return Err(Error::PermissionDenied);
    }
    Ok(())
}

/// Check if a credential may create a device node.
pub fn check_mknod(cred: &VfsCred) -> Result<()> {
    if cred.capable(Capability::SysAdmin) || cred.is_root() {
        return Ok(());
    }
    Err(Error::PermissionDenied)
}

/// Determine effective permission bits for a credential against a file.
fn effective_bits(cred: &VfsCred, owner_uid: u32, owner_gid: u32, mode: u16) -> u16 {
    if cred.euid == owner_uid {
        (mode >> 6) & 7
    } else if cred.egid == owner_gid {
        (mode >> 3) & 7
    } else {
        mode & 7
    }
}

/// Credential cache entry — avoids repeated credential lookups.
#[derive(Debug, Clone, Copy)]
pub struct CredCacheEntry {
    /// Process ID this entry is for.
    pub pid: u32,
    /// Cached credential.
    pub cred: VfsCred,
    /// Generation counter for invalidation.
    pub generation: u32,
}

impl CredCacheEntry {
    /// Create a new cache entry.
    pub const fn new(pid: u32, cred: VfsCred, generation: u32) -> Self {
        CredCacheEntry {
            pid,
            cred,
            generation,
        }
    }
}

/// Small credential cache for VFS operations.
pub struct CredCache {
    entries: [Option<CredCacheEntry>; 32],
    current_gen: u32,
}

impl CredCache {
    /// Create a new empty credential cache.
    pub const fn new() -> Self {
        CredCache {
            entries: [None; 32],
            current_gen: 0,
        }
    }

    /// Look up credentials for a PID.
    pub fn get(&self, pid: u32) -> Option<&VfsCred> {
        for entry in self.entries.iter().flatten() {
            if entry.pid == pid && entry.generation == self.current_gen {
                return Some(&entry.cred);
            }
        }
        None
    }

    /// Insert or update credentials for a PID.
    pub fn put(&mut self, pid: u32, cred: VfsCred) -> Result<()> {
        for slot in &mut self.entries {
            if let Some(e) = slot {
                if e.pid == pid {
                    e.cred = cred;
                    e.generation = self.current_gen;
                    return Ok(());
                }
            }
        }
        for slot in &mut self.entries {
            if slot.is_none() {
                *slot = Some(CredCacheEntry::new(pid, cred, self.current_gen));
                return Ok(());
            }
        }
        // Evict oldest entry.
        self.entries[0] = Some(CredCacheEntry::new(pid, cred, self.current_gen));
        Ok(())
    }

    /// Invalidate all cached credentials (bump generation).
    pub fn invalidate_all(&mut self) {
        self.current_gen = self.current_gen.wrapping_add(1);
    }

    /// Remove cached credentials for a process.
    pub fn remove(&mut self, pid: u32) {
        for slot in &mut self.entries {
            if let Some(e) = slot {
                if e.pid == pid {
                    *slot = None;
                    return;
                }
            }
        }
    }
}

impl Default for CredCache {
    fn default() -> Self {
        Self::new()
    }
}
