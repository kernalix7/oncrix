// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `setreuid` and `setregid` syscall implementations.
//!
//! Sets the real and effective user (or group) IDs of the calling process.
//! A value of -1 means "leave unchanged". These are the traditional
//! UNIX privilege-change calls.
//!
//! POSIX Reference: susv5 functions/setreuid.html
//! POSIX.1-2024 mandatory.

use oncrix_lib::{Error, Result};

/// Sentinel: do not change this ID field.
pub const ID_UNCHANGED: u32 = u32::MAX;

/// Arguments for `setreuid`.
#[derive(Debug, Clone, Copy)]
pub struct SetreuidArgs {
    /// New real UID (ID_UNCHANGED = no change).
    pub ruid: u32,
    /// New effective UID (ID_UNCHANGED = no change).
    pub euid: u32,
}

/// Arguments for `setregid`.
#[derive(Debug, Clone, Copy)]
pub struct SetregidArgs {
    /// New real GID (ID_UNCHANGED = no change).
    pub rgid: u32,
    /// New effective GID (ID_UNCHANGED = no change).
    pub egid: u32,
}

/// Snapshot of real/effective/saved credentials for one ID type.
#[derive(Debug, Clone, Copy, Default)]
pub struct IdPair {
    /// Current real ID.
    pub real: u32,
    /// Current effective ID.
    pub effective: u32,
    /// Current saved set-ID.
    pub saved: u32,
}

impl IdPair {
    /// Create an IdPair with real and effective equal and no saved change.
    pub const fn new(real: u32, effective: u32) -> Self {
        Self {
            real,
            effective,
            saved: effective,
        }
    }

    /// Check if `id` is one of real or effective.
    pub fn contains_re(&self, id: u32) -> bool {
        self.real == id || self.effective == id
    }
}

/// Validate setreuid/setregid arguments for an unprivileged caller.
///
/// Without CAP_SETUID, each non-unchanged value must already be one of
/// the current real, effective, or saved-set IDs (POSIX rule).
pub fn validate_setreuid_unprivileged(new_real: u32, new_eff: u32, current: &IdPair) -> Result<()> {
    let allowed = [current.real, current.effective, current.saved];
    if new_real != ID_UNCHANGED && !allowed.contains(&new_real) {
        return Err(Error::PermissionDenied);
    }
    if new_eff != ID_UNCHANGED && !allowed.contains(&new_eff) {
        return Err(Error::PermissionDenied);
    }
    Ok(())
}

/// Compute the new saved set-UID after a setreuid operation.
///
/// POSIX: if the effective UID is changed and was not equal to the new real
/// UID, the saved set-UID is set to the new effective UID.
pub fn compute_new_saved(old: &IdPair, new_real: u32, new_eff: u32) -> u32 {
    let effective_after = if new_eff != ID_UNCHANGED {
        new_eff
    } else {
        old.effective
    };
    let real_after = if new_real != ID_UNCHANGED {
        new_real
    } else {
        old.real
    };

    // If real UID is being set, the saved set-UID becomes the new effective UID.
    if new_real != ID_UNCHANGED || new_eff != ID_UNCHANGED {
        if real_after != old.real || effective_after != old.effective {
            return effective_after;
        }
    }
    old.saved
}

/// Handle the `setreuid` syscall.
///
/// Sets the real and/or effective UID. Values of ID_UNCHANGED leave the
/// corresponding field unmodified. The saved set-UID is updated per POSIX rules.
///
/// Returns 0 on success, or an error.
pub fn sys_setreuid(args: &SetreuidArgs) -> Result<i64> {
    // Stub: real implementation would:
    // 1. Read current credential IdPair.
    // 2. If not CAP_SETUID: validate_setreuid_unprivileged.
    // 3. Compute new saved via compute_new_saved.
    // 4. prepare_creds, apply changes, commit_creds.
    let _ = args;
    Err(Error::NotImplemented)
}

/// Handle the `setregid` syscall.
///
/// Sets the real and/or effective GID. Mirrors setreuid for GIDs.
///
/// Returns 0 on success, or an error.
pub fn sys_setregid(args: &SetregidArgs) -> Result<i64> {
    // Stub: mirrors setreuid for the group credential.
    let _ = args;
    Err(Error::NotImplemented)
}

/// Check whether the call is a pure effective-only change (real unchanged).
pub fn is_effective_only_change(args_real: u32, _args_eff: u32) -> bool {
    args_real == ID_UNCHANGED
}
