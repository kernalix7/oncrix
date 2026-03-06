// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX capabilities — cap_effective, cap_permitted, cap_inheritable.
//!
//! Implements the POSIX.1e capability model as used in the Linux kernel:
//!
//! - **Permitted** (`cap_p`): The maximum set a thread may use.
//! - **Effective** (`cap_e`): The set currently active (checked at access time).
//! - **Inheritable** (`cap_i`): Preserved across `execve` per capability rules.
//! - **Bounding** (`cap_b`): An upper bound; limits permitted set on `execve`.
//! - **Ambient** (`cap_a`): Automatically inherited by child threads.
//!
//! Each set is represented as a 64-bit bitmask (bits 0–63 map to `CAP_*`
//! constants). Only capabilities with defined meanings in Linux are given
//! named constants here; the rest are reserved.
//!
//! # Privilege Model
//!
//! A thread may only raise bits in `cap_e` that are also set in `cap_p`.
//! `cap_p` can never exceed `cap_b`. Dropping from `cap_p` is irreversible
//! (within that process) unless `cap_b` allows regain via `execve`.
//!
//! Reference: POSIX.1-2024 and Linux capabilities(7).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Capability constants (Linux CAP_* numbering)
// ---------------------------------------------------------------------------

/// Bypass file read permission checks.
pub const CAP_DAC_READ_SEARCH: u8 = 2;
/// Override all DAC access (read/write/execute).
pub const CAP_DAC_OVERRIDE: u8 = 1;
/// Override ownership checks for chown.
pub const CAP_CHOWN: u8 = 0;
/// Bypass setuid/setgid restrictions.
pub const CAP_SETUID: u8 = 7;
/// Bypass setgid restrictions.
pub const CAP_SETGID: u8 = 6;
/// Bypass file permission checks for kill.
pub const CAP_KILL: u8 = 5;
/// Make arbitrary kernel changes (catch-all admin cap).
pub const CAP_SYS_ADMIN: u8 = 21;
/// Use raw sockets.
pub const CAP_NET_RAW: u8 = 13;
/// Bind to privileged ports (<1024).
pub const CAP_NET_BIND_SERVICE: u8 = 10;
/// Configure network interfaces.
pub const CAP_NET_ADMIN: u8 = 12;
/// Load and unload kernel modules.
pub const CAP_SYS_MODULE: u8 = 16;
/// Use chroot.
pub const CAP_SYS_CHROOT: u8 = 18;
/// Send signals to arbitrary processes.
pub const CAP_SYS_PTRACE: u8 = 19;
/// Perform I/O port operations.
pub const CAP_SYS_RAWIO: u8 = 17;
/// Reboot the system.
pub const CAP_SYS_BOOT: u8 = 22;
/// Override resource limits.
pub const CAP_SYS_RESOURCE: u8 = 24;
/// Set system time.
pub const CAP_SYS_TIME: u8 = 25;
/// Set process scheduling policies.
pub const CAP_SYS_NICE: u8 = 23;
/// Manipulate process capabilities.
pub const CAP_SETPCAP: u8 = 8;
/// Lock memory.
pub const CAP_IPC_LOCK: u8 = 14;
/// Override IPC ownership checks.
pub const CAP_IPC_OWNER: u8 = 15;
/// Read audit log.
pub const CAP_AUDIT_READ: u8 = 37;
/// Write audit log.
pub const CAP_AUDIT_WRITE: u8 = 29;
/// Control audit subsystem.
pub const CAP_AUDIT_CONTROL: u8 = 30;
/// Set file capabilities.
pub const CAP_SETFCAP: u8 = 31;
/// Override MAC policies.
pub const CAP_MAC_OVERRIDE: u8 = 32;
/// Allow MAC configuration.
pub const CAP_MAC_ADMIN: u8 = 33;
/// BPF / perf operations.
pub const CAP_BPF: u8 = 39;
/// Performance monitoring.
pub const CAP_PERFMON: u8 = 38;
/// Checkpoint/restore.
pub const CAP_CHECKPOINT_RESTORE: u8 = 40;
/// Total number of defined capabilities.
pub const CAP_LAST: u8 = 41;

// ---------------------------------------------------------------------------
// Capability set
// ---------------------------------------------------------------------------

/// A set of POSIX capabilities represented as a bitmask.
///
/// Bits 0–63 correspond to `CAP_*` values. Bits beyond `CAP_LAST` are
/// reserved and must remain zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct CapSet(u64);

impl CapSet {
    /// Empty capability set.
    pub const EMPTY: Self = Self(0);

    /// Full capability set (all defined capabilities set).
    pub const FULL: Self = Self((1u64 << CAP_LAST) - 1);

    /// Create a capability set from a raw bitmask.
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    /// Return the raw bitmask.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Returns true if the given capability is set.
    pub fn has(self, cap: u8) -> bool {
        if cap >= 64 {
            return false;
        }
        (self.0 >> cap) & 1 == 1
    }

    /// Set a capability bit.
    pub fn set(&mut self, cap: u8) {
        if cap < 64 {
            self.0 |= 1u64 << cap;
        }
    }

    /// Clear a capability bit.
    pub fn clear(&mut self, cap: u8) {
        if cap < 64 {
            self.0 &= !(1u64 << cap);
        }
    }

    /// Intersection (AND) of two sets.
    pub fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Union (OR) of two sets.
    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Difference: bits in self but not in other.
    pub fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Returns true if this set is a subset of `other`.
    pub fn is_subset_of(self, other: Self) -> bool {
        self.intersect(other) == self
    }

    /// Returns true if the set has no capabilities.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

// ---------------------------------------------------------------------------
// Thread capability state
// ---------------------------------------------------------------------------

/// Full POSIX capability state for a single thread/process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadCapState {
    /// Permitted set — maximum effective capabilities the thread may have.
    pub permitted: CapSet,
    /// Effective set — capabilities actually checked by the kernel.
    pub effective: CapSet,
    /// Inheritable set — preserved across `execve`.
    pub inheritable: CapSet,
    /// Bounding set — upper limit on permitted set at `execve`.
    pub bounding: CapSet,
    /// Ambient set — automatically inherited by children.
    pub ambient: CapSet,
}

impl ThreadCapState {
    /// Create a root capability state (all capabilities set).
    pub const fn new_root() -> Self {
        Self {
            permitted: CapSet::FULL,
            effective: CapSet::FULL,
            inheritable: CapSet::EMPTY,
            bounding: CapSet::FULL,
            ambient: CapSet::EMPTY,
        }
    }

    /// Create an unprivileged capability state (no capabilities).
    pub const fn new_unprivileged() -> Self {
        Self {
            permitted: CapSet::EMPTY,
            effective: CapSet::EMPTY,
            inheritable: CapSet::EMPTY,
            bounding: CapSet::FULL,
            ambient: CapSet::EMPTY,
        }
    }

    /// Check whether the thread has `cap` in its effective set.
    pub fn capable(&self, cap: u8) -> bool {
        self.effective.has(cap)
    }

    /// Raise a capability in the effective set.
    ///
    /// Only allowed if the capability is in the permitted set.
    pub fn raise_effective(&mut self, cap: u8) -> Result<()> {
        if !self.permitted.has(cap) {
            return Err(Error::PermissionDenied);
        }
        self.effective.set(cap);
        Ok(())
    }

    /// Drop a capability from the effective set.
    pub fn drop_effective(&mut self, cap: u8) {
        self.effective.clear(cap);
    }

    /// Drop a capability from the permitted set (irreversible without execve).
    pub fn drop_permitted(&mut self, cap: u8) {
        self.permitted.clear(cap);
        // Also drop from effective to maintain the invariant E ⊆ P.
        self.effective.clear(cap);
        // Drop from ambient to maintain A ⊆ P.
        self.ambient.clear(cap);
    }

    /// Drop a capability from the bounding set.
    ///
    /// Requires `CAP_SETPCAP` in the effective set.
    pub fn drop_bounding(&mut self, cap: u8) -> Result<()> {
        if !self.capable(CAP_SETPCAP) {
            return Err(Error::PermissionDenied);
        }
        self.bounding.clear(cap);
        // Bounding constrains permitted and inheritable.
        self.permitted.clear(cap);
        self.effective.clear(cap);
        self.inheritable.clear(cap);
        Ok(())
    }

    /// Raise ambient capability.
    ///
    /// Requires the cap to be in both permitted and inheritable.
    pub fn raise_ambient(&mut self, cap: u8) -> Result<()> {
        if !self.permitted.has(cap) || !self.inheritable.has(cap) {
            return Err(Error::PermissionDenied);
        }
        self.ambient.set(cap);
        Ok(())
    }

    /// Drop ambient capability.
    pub fn drop_ambient(&mut self, cap: u8) {
        self.ambient.clear(cap);
    }

    /// Validate internal consistency of the capability state.
    ///
    /// Enforces: `E ⊆ P`, `A ⊆ P`, `A ⊆ I`, `P ⊆ B`.
    pub fn validate(&self) -> Result<()> {
        if !self.effective.is_subset_of(self.permitted) {
            return Err(Error::InvalidArgument);
        }
        if !self.ambient.is_subset_of(self.permitted) {
            return Err(Error::InvalidArgument);
        }
        if !self.ambient.is_subset_of(self.inheritable) {
            return Err(Error::InvalidArgument);
        }
        if !self.permitted.is_subset_of(self.bounding) {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Compute new capability state after `execve` for a non-set-UID binary.
    ///
    /// `file_permitted` and `file_inheritable` are the file capability sets
    /// stored in the binary's extended attributes.
    pub fn exec_transform(
        &self,
        file_permitted: CapSet,
        file_inheritable: CapSet,
        file_effective_bit: bool,
    ) -> Self {
        // P' = (P ∩ I_file) ∪ (P_file ∩ B)
        let new_permitted = self
            .inheritable
            .intersect(file_inheritable)
            .union(file_permitted.intersect(self.bounding));

        // E' = new_permitted if file effective bit set, else empty.
        // Also include ambient capabilities.
        let new_effective = if file_effective_bit {
            new_permitted
        } else {
            CapSet::EMPTY
        }
        .union(self.ambient);

        // I' = I (inheritable set is preserved across execve).
        // A' = A ∩ new_permitted.
        Self {
            permitted: new_permitted,
            effective: new_effective,
            inheritable: self.inheritable,
            bounding: self.bounding,
            ambient: self.ambient.intersect(new_permitted),
        }
    }
}

impl Default for ThreadCapState {
    fn default() -> Self {
        Self::new_unprivileged()
    }
}

// ---------------------------------------------------------------------------
// Capability check helpers
// ---------------------------------------------------------------------------

/// Check whether a thread with the given capability state is privileged enough
/// to send `signal` to a process owned by `target_uid`.
///
/// Returns `Ok(())` if the check passes, `Err(PermissionDenied)` otherwise.
pub fn check_signal_permission(
    sender_caps: &ThreadCapState,
    sender_uid: u32,
    target_uid: u32,
) -> Result<()> {
    // Same UID → always allowed.
    if sender_uid == target_uid {
        return Ok(());
    }
    // CAP_KILL bypasses UID check.
    if sender_caps.capable(CAP_KILL) {
        return Ok(());
    }
    Err(Error::PermissionDenied)
}

/// Check whether a thread may open a raw socket.
pub fn check_raw_socket(caps: &ThreadCapState) -> Result<()> {
    if caps.capable(CAP_NET_RAW) {
        Ok(())
    } else {
        Err(Error::PermissionDenied)
    }
}

/// Check whether a thread may load a kernel module.
pub fn check_module_load(caps: &ThreadCapState) -> Result<()> {
    if caps.capable(CAP_SYS_MODULE) {
        Ok(())
    } else {
        Err(Error::PermissionDenied)
    }
}
