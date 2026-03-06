// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `capget(2)` and `capset(2)` syscall handlers.
//!
//! Retrieve or modify the capability sets of a thread.
//!
//! # Key behaviours
//!
//! - Capabilities are stored as three 64-bit sets: permitted, inheritable,
//!   and effective.
//! - `capget` returns all three sets for the target thread.
//! - `capset` requires that the new effective ⊆ permitted, and that
//!   the new permitted ⊆ old permitted (capabilities cannot be regained
//!   once dropped without re-exec).
//! - Capability version `_LINUX_CAPABILITY_VERSION_3` uses two 32-bit words
//!   per set (total 64 bits).
//! - `CAP_SETPCAP` is required to raise capabilities in the inheritable set
//!   beyond the bounding set.
//!
//! # References
//!
//! - Linux man pages: `capget(2)`, `capabilities(7)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Capability version
// ---------------------------------------------------------------------------

/// Linux capability ABI version 3 (64-bit capability sets).
pub const _LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

// ---------------------------------------------------------------------------
// Well-known capability constants (bit positions)
// ---------------------------------------------------------------------------

/// Override filesystem uid checks.
pub const CAP_CHOWN: u32 = 0;
/// Make arbitrary changes to file UIDs/GIDs.
pub const CAP_DAC_OVERRIDE: u32 = 1;
/// Bypass discretionary access checks for reading.
pub const CAP_DAC_READ_SEARCH: u32 = 2;
/// Bypass filesystem UID checks for owner operations.
pub const CAP_FOWNER: u32 = 3;
/// Kill any process.
pub const CAP_KILL: u32 = 5;
/// Bypass restrictions on changing UIDs.
pub const CAP_SETUID: u32 = 7;
/// Bypass restrictions on changing GIDs.
pub const CAP_SETGID: u32 = 6;
/// Transfer capabilities to/from permitted set.
pub const CAP_SETPCAP: u32 = 8;
/// Administer system (mount, etc.).
pub const CAP_SYS_ADMIN: u32 = 21;
/// Reboot the system.
pub const CAP_SYS_BOOT: u32 = 22;
/// Lock memory.
pub const CAP_IPC_LOCK: u32 = 14;

/// Number of capability bits in a 64-bit word.
pub const CAP_LAST_CAP: u32 = 40;

// ---------------------------------------------------------------------------
// Capability set
// ---------------------------------------------------------------------------

/// A 64-bit capability set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapSet {
    /// Capability bitmask.
    pub bits: u64,
}

impl CapSet {
    /// Returns `true` if capability `cap` is set.
    pub fn has(&self, cap: u32) -> bool {
        if cap >= 64 {
            return false;
        }
        self.bits & (1u64 << cap) != 0
    }

    /// Set capability `cap`.
    pub fn set(&mut self, cap: u32) {
        if cap < 64 {
            self.bits |= 1u64 << cap;
        }
    }

    /// Clear capability `cap`.
    pub fn clear(&mut self, cap: u32) {
        if cap < 64 {
            self.bits &= !(1u64 << cap);
        }
    }

    /// Returns `true` if `self ⊆ other`.
    pub fn is_subset_of(&self, other: &CapSet) -> bool {
        (self.bits & !other.bits) == 0
    }
}

/// Per-thread capability state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ThreadCaps {
    /// Permitted set.
    pub permitted: CapSet,
    /// Inheritable set.
    pub inheritable: CapSet,
    /// Effective set.
    pub effective: CapSet,
    /// Ambient set.
    pub ambient: CapSet,
    /// Bounding set.
    pub bounding: CapSet,
}

impl ThreadCaps {
    /// Construct capabilities for a fully privileged thread (all caps set).
    pub fn privileged() -> Self {
        let all = CapSet { bits: u64::MAX };
        Self {
            permitted: all,
            inheritable: all,
            effective: all,
            ambient: all,
            bounding: all,
        }
    }
}

// ---------------------------------------------------------------------------
// Header / data structures (Linux ABI)
// ---------------------------------------------------------------------------

/// `cap_user_header_t` — capability header.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct CapUserHeader {
    /// Capability version (should be `_LINUX_CAPABILITY_VERSION_3`).
    pub version: u32,
    /// Thread PID (0 = calling thread).
    pub pid: i32,
}

/// `cap_user_data_t[2]` — two 32-bit words per set (effective, permitted,
/// inheritable) for version 3.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct CapUserData {
    /// Effective capabilities (low 32 bits).
    pub effective_lo: u32,
    /// Permitted capabilities (low 32 bits).
    pub permitted_lo: u32,
    /// Inheritable capabilities (low 32 bits).
    pub inheritable_lo: u32,
    /// Effective capabilities (high 32 bits).
    pub effective_hi: u32,
    /// Permitted capabilities (high 32 bits).
    pub permitted_hi: u32,
    /// Inheritable capabilities (high 32 bits).
    pub inheritable_hi: u32,
}

impl CapUserData {
    /// Build from `ThreadCaps`.
    pub fn from_caps(caps: &ThreadCaps) -> Self {
        Self {
            effective_lo: caps.effective.bits as u32,
            effective_hi: (caps.effective.bits >> 32) as u32,
            permitted_lo: caps.permitted.bits as u32,
            permitted_hi: (caps.permitted.bits >> 32) as u32,
            inheritable_lo: caps.inheritable.bits as u32,
            inheritable_hi: (caps.inheritable.bits >> 32) as u32,
        }
    }

    /// Convert back to capability bits.
    pub fn to_effective(&self) -> u64 {
        (self.effective_lo as u64) | ((self.effective_hi as u64) << 32)
    }
    /// Convert back to permitted bits.
    pub fn to_permitted(&self) -> u64 {
        (self.permitted_lo as u64) | ((self.permitted_hi as u64) << 32)
    }
    /// Convert back to inheritable bits.
    pub fn to_inheritable(&self) -> u64 {
        (self.inheritable_lo as u64) | ((self.inheritable_hi as u64) << 32)
    }
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `capget(2)`.
///
/// Returns the capability data for the calling thread.
///
/// # Errors
///
/// | `Error`           | Condition                              |
/// |-------------------|----------------------------------------|
/// | `InvalidArgument` | Unsupported capability version         |
pub fn do_capget(hdr: &CapUserHeader, caps: &ThreadCaps) -> Result<CapUserData> {
    if hdr.version != _LINUX_CAPABILITY_VERSION_3 && hdr.version != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(CapUserData::from_caps(caps))
}

/// Handler for `capset(2)`.
///
/// Updates the capability sets.  Enforces that:
/// - new effective ⊆ new permitted.
/// - new permitted ⊆ old permitted (cannot regain dropped caps).
///
/// # Errors
///
/// | `Error`           | Condition                                    |
/// |-------------------|----------------------------------------------|
/// | `InvalidArgument` | Unsupported version or effective > permitted |
/// | `PermissionDenied`| Trying to raise permitted beyond old permitted|
pub fn do_capset(hdr: &CapUserHeader, caps: &mut ThreadCaps, data: &CapUserData) -> Result<()> {
    if hdr.version != _LINUX_CAPABILITY_VERSION_3 && hdr.version != 0 {
        return Err(Error::InvalidArgument);
    }

    let new_eff = CapSet {
        bits: data.to_effective(),
    };
    let new_perm = CapSet {
        bits: data.to_permitted(),
    };
    let new_inh = CapSet {
        bits: data.to_inheritable(),
    };

    // Effective must be subset of permitted.
    if !new_eff.is_subset_of(&new_perm) {
        return Err(Error::InvalidArgument);
    }
    // New permitted must not exceed old permitted.
    if !new_perm.is_subset_of(&caps.permitted) {
        return Err(Error::PermissionDenied);
    }

    caps.effective = new_eff;
    caps.permitted = new_perm;
    caps.inheritable = new_inh;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr() -> CapUserHeader {
        CapUserHeader {
            version: _LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        }
    }

    #[test]
    fn capget_returns_data() {
        let caps = ThreadCaps::privileged();
        let data = do_capget(&hdr(), &caps).unwrap();
        assert_eq!(data.permitted_lo, u32::MAX);
    }

    #[test]
    fn capset_drop_cap() {
        let mut caps = ThreadCaps::privileged();
        // Drop CAP_SYS_ADMIN from permitted and effective.
        let mut data = CapUserData::from_caps(&caps);
        data.permitted_lo &= !(1 << CAP_SYS_ADMIN);
        data.effective_lo &= !(1 << CAP_SYS_ADMIN);
        do_capset(&hdr(), &mut caps, &data).unwrap();
        assert!(!caps.effective.has(CAP_SYS_ADMIN));
    }

    #[test]
    fn capset_raise_above_permitted_fails() {
        let mut caps = ThreadCaps::default(); // no caps
        let data = CapUserData::from_caps(&ThreadCaps::privileged());
        assert_eq!(
            do_capset(&hdr(), &mut caps, &data),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn capset_effective_exceeds_permitted_fails() {
        let mut caps = ThreadCaps::privileged();
        let mut data = CapUserData::from_caps(&caps);
        // Set an effective bit that's not in permitted.
        data.effective_hi = 0xFFFF_FFFF;
        data.permitted_hi = 0;
        assert_eq!(
            do_capset(&hdr(), &mut caps, &data),
            Err(Error::InvalidArgument)
        );
    }
}
