// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `capset` syscall implementation.
//!
//! Sets the capabilities of the calling thread or another thread
//! identified by PID. Used by privilege-separation daemons to drop
//! specific capabilities after initialization.
//!
//! Linux-specific capability interface. Not in POSIX.

use oncrix_lib::{Error, Result};

/// Capability header version (v3 — 64-bit, two 32-bit halves).
pub const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;

/// Number of 32-bit words in a capability set (version 3).
pub const CAP_WORDS: usize = 2;

/// Capability header structure passed to/from user space.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct CapUserHeader {
    /// Capability ABI version (must be LINUX_CAPABILITY_VERSION_3).
    pub version: u32,
    /// PID of the target thread (0 = calling thread).
    pub pid: i32,
}

impl CapUserHeader {
    /// Create a header for the calling thread.
    pub const fn new() -> Self {
        Self {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        }
    }

    /// Validate that the version field is recognized.
    pub fn is_version_valid(&self) -> bool {
        self.version == LINUX_CAPABILITY_VERSION_3
    }
}

/// Capability data structure (one 32-bit slice of a 64-bit cap set).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct CapUserData {
    /// Effective capabilities bitmask for this half.
    pub effective: u32,
    /// Permitted capabilities bitmask for this half.
    pub permitted: u32,
    /// Inheritable capabilities bitmask for this half.
    pub inheritable: u32,
}

impl CapUserData {
    /// Create an empty (no capabilities) data word.
    pub const fn new() -> Self {
        Self {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }
    }

    /// Check that effective ⊆ permitted (a kernel invariant).
    pub fn is_consistent(&self) -> bool {
        (self.effective & !self.permitted) == 0
    }
}

/// Full 64-bit capability set built from two CapUserData words.
#[derive(Debug, Clone, Copy, Default)]
pub struct CapSet64 {
    /// Effective capabilities (64 bits).
    pub effective: u64,
    /// Permitted capabilities (64 bits).
    pub permitted: u64,
    /// Inheritable capabilities (64 bits).
    pub inheritable: u64,
}

impl CapSet64 {
    /// Build a CapSet64 from two user-space data words (low, high).
    pub fn from_words(low: &CapUserData, high: &CapUserData) -> Self {
        Self {
            effective: (low.effective as u64) | ((high.effective as u64) << 32),
            permitted: (low.permitted as u64) | ((high.permitted as u64) << 32),
            inheritable: (low.inheritable as u64) | ((high.inheritable as u64) << 32),
        }
    }

    /// Check that effective ⊆ permitted (invariant required by the kernel).
    pub fn is_consistent(&self) -> bool {
        (self.effective & !self.permitted) == 0
    }

    /// Check that permitted ⊆ bounding_set (drop beyond bounding set is an error).
    pub fn within_bounding_set(&self, bounding: u64) -> bool {
        (self.permitted & !bounding) == 0
    }
}

/// Arguments for the `capset` syscall.
#[derive(Debug)]
pub struct CapsetArgs {
    /// Pointer to user-space `CapUserHeader`.
    pub header_ptr: usize,
    /// Pointer to user-space `CapUserData` array (2 elements for v3).
    pub data_ptr: usize,
}

/// Validate `capset` arguments.
pub fn validate_capset_args(args: &CapsetArgs) -> Result<()> {
    if args.header_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if args.data_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Handle the `capset` syscall.
///
/// Sets the capabilities of the thread identified by `header.pid`
/// (or the calling thread if pid == 0). Requires CAP_SETPCAP to set
/// capabilities on another thread.
///
/// Returns 0 on success, or an error.
pub fn sys_capset(args: &CapsetArgs) -> Result<i64> {
    validate_capset_args(args)?;
    // Stub: real implementation would:
    // 1. copy_from_user CapUserHeader; validate version.
    // 2. copy_from_user CapUserData[2].
    // 3. Build CapSet64 from the two words.
    // 4. Validate consistency (effective ⊆ permitted).
    // 5. If pid != 0: check CAP_SETPCAP, resolve pid to task.
    // 6. Commit new capabilities to the task's cred.
    Err(Error::NotImplemented)
}

/// Check whether the capability set has a specific capability.
///
/// `cap` is the Linux capability number (0..63).
pub fn has_cap(capset: &CapSet64, cap: u32) -> bool {
    if cap >= 64 {
        return false;
    }
    (capset.effective >> cap) & 1 != 0
}

/// Drop a capability from both effective and permitted sets.
pub fn drop_cap(capset: &mut CapSet64, cap: u32) {
    if cap >= 64 {
        return;
    }
    let mask = !(1u64 << cap);
    capset.effective &= mask;
    capset.permitted &= mask;
}
