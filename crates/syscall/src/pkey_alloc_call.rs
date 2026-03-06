// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `pkey_alloc` syscall implementation.
//!
//! Allocates a Protection Key (pkey) for use with `pkey_mprotect`.
//! Protection keys provide per-thread memory access control without
//! changing page table entries, using the PKRU register on x86.
//!
//! Linux-specific (since 4.9). Not in POSIX.

use oncrix_lib::{Error, Result};

/// Maximum number of protection keys on x86_64 (PKRU has 16 domains).
pub const PKEY_MAX: u32 = 16;

/// pkey_alloc flags — must be 0 in the current ABI.
pub const PKEY_ALLOC_FLAGS_MASK: u32 = 0;

/// Initial access rights for the allocated pkey.
pub struct PkeyAccessRights;

impl PkeyAccessRights {
    /// Disable access (reads and writes fault).
    pub const PKEY_DISABLE_ACCESS: u32 = 0x1;
    /// Disable writes (writes fault, reads succeed).
    pub const PKEY_DISABLE_WRITE: u32 = 0x2;
}

/// Arguments for the `pkey_alloc` syscall.
#[derive(Debug, Clone, Copy)]
pub struct PkeyAllocArgs {
    /// Flags (must be 0).
    pub flags: u32,
    /// Initial access rights for the new pkey.
    pub init_val: u32,
}

/// Result of a successful pkey allocation.
#[derive(Debug, Clone, Copy)]
pub struct PkeyAllocResult {
    /// Allocated pkey number (0..PKEY_MAX-1).
    pub pkey: u32,
    /// Access rights installed at allocation time.
    pub init_val: u32,
}

impl PkeyAllocResult {
    /// Create a new allocation result.
    pub const fn new(pkey: u32, init_val: u32) -> Self {
        Self { pkey, init_val }
    }

    /// Check if this pkey starts with write-disabled access.
    pub fn write_disabled(&self) -> bool {
        (self.init_val & PkeyAccessRights::PKEY_DISABLE_WRITE) != 0
    }
}

/// Validate `pkey_alloc` arguments.
///
/// The `flags` field must be 0. The `init_val` must contain only known
/// access right bits.
pub fn validate_pkey_alloc_args(args: &PkeyAllocArgs) -> Result<()> {
    if args.flags != 0 {
        return Err(Error::InvalidArgument);
    }
    let known_rights = PkeyAccessRights::PKEY_DISABLE_ACCESS | PkeyAccessRights::PKEY_DISABLE_WRITE;
    if args.init_val & !known_rights != 0 {
        return Err(Error::InvalidArgument);
    }
    // DISABLE_ACCESS implies DISABLE_WRITE; do not allow only DISABLE_ACCESS.
    if (args.init_val & PkeyAccessRights::PKEY_DISABLE_ACCESS) != 0
        && (args.init_val & PkeyAccessRights::PKEY_DISABLE_WRITE) == 0
    {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Check whether protection keys are supported by the current CPU.
///
/// On x86_64 this checks CPUID leaf 7, sub-leaf 0, bit 3 (PKU).
pub fn pkeys_supported() -> bool {
    // Stub: real check reads CPUID.
    false
}

/// Find a free pkey in the per-process pkey allocation bitmap.
///
/// Returns the pkey number or `Err(OutOfMemory)` if all keys are used.
pub fn alloc_pkey(bitmap: u32) -> Result<u32> {
    for i in 0..PKEY_MAX {
        if (bitmap >> i) & 1 == 0 {
            return Ok(i);
        }
    }
    Err(Error::OutOfMemory)
}

/// Handle the `pkey_alloc` syscall.
///
/// Allocates an unused protection key from the per-process bitmap and
/// sets its PKRU bits to reflect `init_val`. Pkey 0 is the default key
/// and cannot be allocated; the kernel starts from pkey 1.
///
/// Returns the allocated pkey number (>= 1) on success, or an error.
pub fn sys_pkey_alloc(args: &PkeyAllocArgs) -> Result<i64> {
    validate_pkey_alloc_args(args)?;
    if !pkeys_supported() {
        return Err(Error::NotImplemented);
    }
    // Stub: real implementation would:
    // 1. Lock the per-mm pkey bitmap.
    // 2. Find the first unset bit (>= 1).
    // 3. Set the bit in the bitmap.
    // 4. Update PKRU to set init_val for the new pkey.
    // 5. Return the pkey number.
    Err(Error::NotImplemented)
}

/// Update the PKRU register to apply given access rights to a pkey.
///
/// PKRU stores 2 bits per pkey: bit 0 = disable access, bit 1 = disable write.
pub fn update_pkru(pkru: u32, pkey: u32, access_rights: u32) -> u32 {
    if pkey >= PKEY_MAX {
        return pkru;
    }
    let shift = pkey * 2;
    let mask = 0x3u32 << shift;
    (pkru & !mask) | ((access_rights & 0x3) << shift)
}
