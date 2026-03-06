// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Process credentials (UID/GID) management.
//!
//! Implements POSIX process credentials including real, effective, and
//! saved set-user/group IDs, plus supplementary group membership.
//! Follows POSIX.1-2024 semantics for `setuid`, `setgid`, and related
//! system calls.

use oncrix_lib::{Error, Result};

// ── Type aliases ──────────────────────────────────────────────────

/// User identifier (POSIX `uid_t`).
pub type Uid = u32;

/// Group identifier (POSIX `gid_t`).
pub type Gid = u32;

// ── Constants ─────────────────────────────────────────────────────

/// UID of the superuser (root).
pub const ROOT_UID: Uid = 0;

/// GID of the superuser (root) group.
pub const ROOT_GID: Gid = 0;

/// UID of the `nobody` user (unprivileged placeholder).
pub const NOBODY_UID: Uid = 65534;

/// GID of the `nobody` group (unprivileged placeholder).
pub const NOBODY_GID: Gid = 65534;

/// Maximum number of supplementary groups per process.
///
/// Matches the POSIX `NGROUPS_MAX` minimum value used by Linux.
pub const NGROUPS_MAX: usize = 32;

// ── Credentials struct ───────────────────────────────────────────

/// Process credentials holding real, effective, and saved-set IDs.
///
/// Each process carries a full set of POSIX credentials:
/// - **real** (`uid`/`gid`): inherited from the parent, identifies
///   the user who started the process.
/// - **effective** (`euid`/`egid`): used for permission checks.
/// - **saved set-user/group-ID** (`suid`/`sgid`): preserved across
///   `execve` of a set-user-ID binary so the process can later
///   restore its effective ID.
///
/// Supplementary groups provide additional group memberships
/// beyond the primary GID, checked by [`in_group`](Self::in_group).
#[derive(Debug, Clone, Copy)]
pub struct Credentials {
    /// Real user ID.
    uid: Uid,
    /// Real group ID.
    gid: Gid,
    /// Effective user ID (used for permission checks).
    euid: Uid,
    /// Effective group ID.
    egid: Gid,
    /// Saved set-user-ID (preserved across `execve`).
    suid: Uid,
    /// Saved set-group-ID.
    sgid: Gid,
    /// Supplementary group list (fixed-size array).
    supplementary_groups: [Gid; NGROUPS_MAX],
    /// Number of valid entries in `supplementary_groups`.
    ngroups: usize,
}

impl Credentials {
    /// Create root credentials (all IDs set to 0).
    ///
    /// Used for the initial kernel process and privileged daemons.
    pub fn root() -> Self {
        Self {
            uid: ROOT_UID,
            gid: ROOT_GID,
            euid: ROOT_UID,
            egid: ROOT_GID,
            suid: ROOT_UID,
            sgid: ROOT_GID,
            supplementary_groups: [0; NGROUPS_MAX],
            ngroups: 0,
        }
    }

    /// Create credentials with the given UID and GID.
    ///
    /// Sets all user IDs (real, effective, saved) to `uid` and all
    /// group IDs to `gid`. Supplementary groups are empty.
    pub fn new(uid: Uid, gid: Gid) -> Self {
        Self {
            uid,
            gid,
            euid: uid,
            egid: gid,
            suid: uid,
            sgid: gid,
            supplementary_groups: [0; NGROUPS_MAX],
            ngroups: 0,
        }
    }

    /// Return `true` if the process has superuser privileges.
    ///
    /// Checks the effective UID, which is the ID used for all
    /// permission decisions.
    pub fn is_root(&self) -> bool {
        self.euid == ROOT_UID
    }

    /// Get the real user ID.
    pub fn uid(&self) -> Uid {
        self.uid
    }

    /// Get the real group ID.
    pub fn gid(&self) -> Gid {
        self.gid
    }

    /// Get the effective user ID.
    pub fn euid(&self) -> Uid {
        self.euid
    }

    /// Get the effective group ID.
    pub fn egid(&self) -> Gid {
        self.egid
    }

    /// Get the saved set-user-ID.
    pub fn suid(&self) -> Uid {
        self.suid
    }

    /// Get the saved set-group-ID.
    pub fn sgid(&self) -> Gid {
        self.sgid
    }

    /// Get the number of supplementary groups.
    pub fn ngroups(&self) -> usize {
        self.ngroups
    }

    /// Get a slice of the supplementary groups.
    pub fn groups(&self) -> &[Gid] {
        &self.supplementary_groups[..self.ngroups]
    }

    /// Set the real, effective, and saved user ID (`setuid`).
    ///
    /// # POSIX semantics
    ///
    /// - If the caller has superuser privileges (`euid == 0`), all
    ///   three IDs (real, effective, saved) are set to `uid`.
    /// - Otherwise, `uid` must equal the current real UID or the
    ///   saved set-user-ID; only the effective UID is changed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PermissionDenied`] if the caller lacks
    /// privileges and `uid` does not match either the real UID or
    /// the saved set-user-ID.
    pub fn set_uid(&mut self, uid: Uid) -> Result<()> {
        if self.euid == ROOT_UID {
            self.uid = uid;
            self.euid = uid;
            self.suid = uid;
            Ok(())
        } else if uid == self.uid || uid == self.suid {
            self.euid = uid;
            Ok(())
        } else {
            Err(Error::PermissionDenied)
        }
    }

    /// Set the real, effective, and saved group ID (`setgid`).
    ///
    /// # POSIX semantics
    ///
    /// - If the caller has superuser privileges (`euid == 0`), all
    ///   three IDs (real, effective, saved) are set to `gid`.
    /// - Otherwise, `gid` must equal the current real GID or the
    ///   saved set-group-ID; only the effective GID is changed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PermissionDenied`] if the caller lacks
    /// privileges and `gid` does not match either the real GID or
    /// the saved set-group-ID.
    pub fn set_gid(&mut self, gid: Gid) -> Result<()> {
        if self.euid == ROOT_UID {
            self.gid = gid;
            self.egid = gid;
            self.sgid = gid;
            Ok(())
        } else if gid == self.gid || gid == self.sgid {
            self.egid = gid;
            Ok(())
        } else {
            Err(Error::PermissionDenied)
        }
    }

    /// Set the effective user ID (`seteuid`).
    ///
    /// # POSIX semantics
    ///
    /// - If the caller has superuser privileges (`euid == 0`), any
    ///   value is accepted.
    /// - Otherwise, `euid` must equal the current real UID or the
    ///   saved set-user-ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PermissionDenied`] if the caller lacks
    /// privileges and `euid` does not match either the real UID or
    /// the saved set-user-ID.
    pub fn set_euid(&mut self, euid: Uid) -> Result<()> {
        if self.euid == ROOT_UID || euid == self.uid || euid == self.suid {
            self.euid = euid;
            Ok(())
        } else {
            Err(Error::PermissionDenied)
        }
    }

    /// Set the effective group ID (`setegid`).
    ///
    /// # POSIX semantics
    ///
    /// - If the caller has superuser privileges (`euid == 0`), any
    ///   value is accepted.
    /// - Otherwise, `egid` must equal the current real GID or the
    ///   saved set-group-ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PermissionDenied`] if the caller lacks
    /// privileges and `egid` does not match either the real GID or
    /// the saved set-group-ID.
    pub fn set_egid(&mut self, egid: Gid) -> Result<()> {
        if self.euid == ROOT_UID || egid == self.gid || egid == self.sgid {
            self.egid = egid;
            Ok(())
        } else {
            Err(Error::PermissionDenied)
        }
    }

    /// Set the supplementary group list (`setgroups`).
    ///
    /// Replaces the entire supplementary group list. The list length
    /// must not exceed [`NGROUPS_MAX`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `groups` contains more
    /// than [`NGROUPS_MAX`] entries.
    pub fn set_groups(&mut self, groups: &[Gid]) -> Result<()> {
        if groups.len() > NGROUPS_MAX {
            return Err(Error::InvalidArgument);
        }
        let len = groups.len();
        self.supplementary_groups[..len].copy_from_slice(groups);
        // Zero out remaining slots for deterministic state.
        let mut i = len;
        while i < NGROUPS_MAX {
            self.supplementary_groups[i] = 0;
            i += 1;
        }
        self.ngroups = len;
        Ok(())
    }

    /// Check if the process belongs to the given group.
    ///
    /// Returns `true` if `gid` matches the real GID, the effective
    /// GID, or any entry in the supplementary group list.
    pub fn in_group(&self, gid: Gid) -> bool {
        if gid == self.gid || gid == self.egid {
            return true;
        }
        let mut i = 0;
        while i < self.ngroups {
            if self.supplementary_groups[i] == gid {
                return true;
            }
            i += 1;
        }
        false
    }
}
