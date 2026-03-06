// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Inode permission checking subsystem.
//!
//! Implements POSIX permission checks for inode access, including standard
//! Unix DAC (Discretionary Access Control) mode bits and special cases
//! such as sticky bit semantics on directories.

use oncrix_lib::{Error, Result};

/// Permission bit constants matching POSIX mode bits.
pub mod mode {
    /// Set-UID on execution.
    pub const S_ISUID: u16 = 0o4000;
    /// Set-GID on execution.
    pub const S_ISGID: u16 = 0o2000;
    /// Sticky bit.
    pub const S_ISVTX: u16 = 0o1000;
    /// Owner read permission.
    pub const S_IRUSR: u16 = 0o0400;
    /// Owner write permission.
    pub const S_IWUSR: u16 = 0o0200;
    /// Owner execute permission.
    pub const S_IXUSR: u16 = 0o0100;
    /// Group read permission.
    pub const S_IRGRP: u16 = 0o0040;
    /// Group write permission.
    pub const S_IWGRP: u16 = 0o0020;
    /// Group execute permission.
    pub const S_IXGRP: u16 = 0o0010;
    /// Other read permission.
    pub const S_IROTH: u16 = 0o0004;
    /// Other write permission.
    pub const S_IWOTH: u16 = 0o0002;
    /// Other execute permission.
    pub const S_IXOTH: u16 = 0o0001;
}

/// Access request type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessMask(pub u32);

impl AccessMask {
    /// Read access.
    pub const READ: u32 = 4;
    /// Write access.
    pub const WRITE: u32 = 2;
    /// Execute/search access.
    pub const EXEC: u32 = 1;
    /// Check file existence only.
    pub const EXISTS: u32 = 0;

    /// Create from raw value.
    pub const fn from_raw(v: u32) -> Self {
        AccessMask(v)
    }

    /// Check if read access is requested.
    pub fn wants_read(self) -> bool {
        self.0 & Self::READ != 0
    }

    /// Check if write access is requested.
    pub fn wants_write(self) -> bool {
        self.0 & Self::WRITE != 0
    }

    /// Check if execute access is requested.
    pub fn wants_exec(self) -> bool {
        self.0 & Self::EXEC != 0
    }
}

/// Credential snapshot for a permission check.
#[derive(Debug, Clone, Copy)]
pub struct Cred {
    /// Effective user ID.
    pub euid: u32,
    /// Effective group ID.
    pub egid: u32,
    /// Supplementary group IDs (up to 16).
    pub groups: [u32; 16],
    /// Number of supplementary groups.
    pub ngroups: usize,
    /// Whether the process has CAP_DAC_OVERRIDE.
    pub cap_dac_override: bool,
    /// Whether the process has CAP_DAC_READ_SEARCH.
    pub cap_dac_read_search: bool,
}

impl Cred {
    /// Create a root credential.
    pub const fn root() -> Self {
        Cred {
            euid: 0,
            egid: 0,
            groups: [0u32; 16],
            ngroups: 0,
            cap_dac_override: true,
            cap_dac_read_search: true,
        }
    }

    /// Check if the credential belongs to a given group (primary or supplementary).
    pub fn in_group(&self, gid: u32) -> bool {
        if self.egid == gid {
            return true;
        }
        self.groups[..self.ngroups].contains(&gid)
    }
}

/// Inode ownership and mode information needed for permission checks.
#[derive(Debug, Clone, Copy)]
pub struct InodeMeta {
    /// Inode owner UID.
    pub uid: u32,
    /// Inode owner GID.
    pub gid: u32,
    /// Permission mode bits.
    pub mode: u16,
}

impl InodeMeta {
    /// Create inode metadata.
    pub const fn new(uid: u32, gid: u32, mode: u16) -> Self {
        InodeMeta { uid, gid, mode }
    }
}

/// Extract the three permission triplets from a mode word.
///
/// Returns `(owner_rwx, group_rwx, other_rwx)` as 3-bit values.
pub fn permission_triplets(mode: u16) -> (u8, u8, u8) {
    let owner = ((mode >> 6) & 7) as u8;
    let group = ((mode >> 3) & 7) as u8;
    let other = (mode & 7) as u8;
    (owner, group, other)
}

/// Perform a standard POSIX DAC permission check.
///
/// Returns `Ok(())` if the access is permitted, `Err(PermissionDenied)` otherwise.
pub fn inode_permission(meta: &InodeMeta, cred: &Cred, mask: AccessMask) -> Result<()> {
    // Existence check always succeeds if we can see the inode.
    if mask.0 == AccessMask::EXISTS {
        return Ok(());
    }
    // Root bypass: CAP_DAC_OVERRIDE bypasses write and execute checks;
    // CAP_DAC_READ_SEARCH bypasses read and directory search checks.
    if cred.euid == 0 {
        if mask.wants_exec() {
            // Root can execute if any execute bit is set.
            let (o, g, oth) = permission_triplets(meta.mode);
            if (o | g | oth) & 1 != 0 || !mask.wants_exec() {
                return Ok(());
            }
        } else {
            return Ok(());
        }
    }
    let (owner_rwx, group_rwx, other_rwx) = permission_triplets(meta.mode);
    let effective_bits = if cred.euid == meta.uid {
        owner_rwx
    } else if cred.in_group(meta.gid) {
        group_rwx
    } else {
        other_rwx
    };
    // Check each requested permission bit.
    if mask.wants_read() && effective_bits & 4 == 0 {
        if cred.cap_dac_read_search {
            return Ok(());
        }
        if cred.cap_dac_override {
            return Ok(());
        }
        return Err(Error::PermissionDenied);
    }
    if mask.wants_write() && effective_bits & 2 == 0 {
        if cred.cap_dac_override {
            return Ok(());
        }
        return Err(Error::PermissionDenied);
    }
    if mask.wants_exec() && effective_bits & 1 == 0 {
        if cred.cap_dac_override {
            // CAP_DAC_OVERRIDE only works for execute if some execute bit is set.
            let (o, g, oth) = (owner_rwx, group_rwx, other_rwx);
            if (o | g | oth) & 1 != 0 {
                return Ok(());
            }
        }
        return Err(Error::PermissionDenied);
    }
    Ok(())
}

/// Check sticky bit semantics for directory entry removal.
///
/// A file in a sticky directory can only be unlinked by:
/// - The file's owner.
/// - The directory's owner.
/// - The superuser.
pub fn sticky_check(dir_meta: &InodeMeta, file_uid: u32, cred: &Cred) -> Result<()> {
    let sticky = dir_meta.mode & mode::S_ISVTX != 0;
    if !sticky {
        return Ok(());
    }
    if cred.euid == 0 || cred.euid == dir_meta.uid || cred.euid == file_uid {
        return Ok(());
    }
    Err(Error::PermissionDenied)
}

/// Check if a new mode is valid for chmod.
///
/// Non-root cannot set the SGID bit on a file whose group they don't belong to.
pub fn may_setattr_mode(new_mode: u16, inode_gid: u32, cred: &Cred) -> Result<()> {
    if cred.euid == 0 {
        return Ok(());
    }
    // Non-owner cannot change mode.
    // (Owner check done by caller — just validate SGID rule here.)
    if new_mode & mode::S_ISGID != 0 && !cred.in_group(inode_gid) {
        return Err(Error::PermissionDenied);
    }
    Ok(())
}
