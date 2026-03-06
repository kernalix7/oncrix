// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `setresuid` and `setresgid` syscall implementations.
//!
//! Sets the real, effective, and saved-set user (or group) IDs of the
//! calling process. A value of -1 (as u32::MAX) means "leave unchanged".
//! Requires CAP_SETUID / CAP_SETGID for arbitrary changes.
//!
//! Linux-specific extension; not in strict POSIX but widely available.

use oncrix_lib::{Error, Result};

/// Sentinel meaning "do not change this ID field".
pub const ID_UNCHANGED: u32 = u32::MAX;

/// Arguments for `setresuid`.
#[derive(Debug, Clone, Copy)]
pub struct SetresuidArgs {
    /// New real UID (-1 = no change).
    pub ruid: u32,
    /// New effective UID (-1 = no change).
    pub euid: u32,
    /// New saved set-UID (-1 = no change).
    pub suid: u32,
}

/// Arguments for `setresgid`.
#[derive(Debug, Clone, Copy)]
pub struct SetresgidArgs {
    /// New real GID (-1 = no change).
    pub rgid: u32,
    /// New effective GID (-1 = no change).
    pub egid: u32,
    /// New saved set-GID (-1 = no change).
    pub sgid: u32,
}

/// Current credential triple (real, effective, saved) for one ID type.
#[derive(Debug, Clone, Copy, Default)]
pub struct IdTriple {
    pub real: u32,
    pub effective: u32,
    pub saved: u32,
}

impl IdTriple {
    /// Create an IdTriple with all fields equal.
    pub const fn uniform(id: u32) -> Self {
        Self {
            real: id,
            effective: id,
            saved: id,
        }
    }

    /// Return true if `id` is one of real, effective, or saved.
    pub fn contains(&self, id: u32) -> bool {
        self.real == id || self.effective == id || self.saved == id
    }
}

/// Validate a setresuid/setresgid argument triple for unprivileged use.
///
/// Without CAP_SETUID, each non-unchanged value must be one of the
/// existing real, effective, or saved-set IDs.
pub fn validate_unprivileged(args_triple: (u32, u32, u32), current: &IdTriple) -> Result<()> {
    let (r, e, s) = args_triple;
    for id in [r, e, s] {
        if id != ID_UNCHANGED && !current.contains(id) {
            return Err(Error::PermissionDenied);
        }
    }
    Ok(())
}

/// Apply setresuid changes to a mutable IdTriple, respecting ID_UNCHANGED.
pub fn apply_res_id(triple: &mut IdTriple, new_real: u32, new_eff: u32, new_saved: u32) {
    if new_real != ID_UNCHANGED {
        triple.real = new_real;
    }
    if new_eff != ID_UNCHANGED {
        triple.effective = new_eff;
    }
    if new_saved != ID_UNCHANGED {
        triple.saved = new_saved;
    }
}

/// Handle the `setresuid` syscall.
///
/// Sets real, effective, and saved-set UIDs. Values of ID_UNCHANGED (u32::MAX)
/// leave the corresponding field unmodified.
///
/// With CAP_SETUID: any UID may be set.
/// Without: each new value must be one of the current r/e/s UIDs.
///
/// Returns 0 on success, or an error.
pub fn sys_setresuid(args: &SetresuidArgs) -> Result<i64> {
    // Stub: real implementation would:
    // 1. Read current->cred uid triple.
    // 2. Check CAP_SETUID; if not privileged, validate_unprivileged.
    // 3. prepare_creds, apply_res_id, commit_creds.
    let _ = args;
    Err(Error::NotImplemented)
}

/// Handle the `setresgid` syscall.
///
/// Sets real, effective, and saved-set GIDs. Values of ID_UNCHANGED leave
/// the corresponding field unmodified.
///
/// Returns 0 on success, or an error.
pub fn sys_setresgid(args: &SetresgidArgs) -> Result<i64> {
    // Stub: real implementation mirrors setresuid for GIDs.
    let _ = args;
    Err(Error::NotImplemented)
}

/// Check whether two IdTriples represent a privilege drop (new ⊆ old).
///
/// A privilege drop is safe; a privilege escalation requires CAP_SETUID.
pub fn is_privilege_drop(old: &IdTriple, new: &IdTriple) -> bool {
    old.contains(new.real) && old.contains(new.effective) && old.contains(new.saved)
}
