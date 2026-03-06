// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `pkey_free` syscall implementation.
//!
//! Frees a protection key previously allocated by `pkey_alloc`, making
//! it available for future allocation. Any memory ranges still tagged
//! with this pkey become inaccessible until re-tagged via `pkey_mprotect`.
//!
//! Linux-specific (since 4.9). Not in POSIX.

use oncrix_lib::{Error, Result};

/// Maximum number of protection keys on x86_64.
pub const PKEY_MAX: u32 = 16;

/// The default pkey (0) cannot be freed.
pub const PKEY_DEFAULT: u32 = 0;

/// Arguments for the `pkey_free` syscall.
#[derive(Debug, Clone, Copy)]
pub struct PkeyFreeArgs {
    /// Protection key to free (must be >= 1 and previously allocated).
    pub pkey: u32,
}

/// Validate `pkey_free` arguments.
///
/// Checks that the pkey is within the valid range and is not the default key.
pub fn validate_pkey_free_args(args: &PkeyFreeArgs) -> Result<()> {
    if args.pkey == PKEY_DEFAULT {
        return Err(Error::InvalidArgument);
    }
    if args.pkey >= PKEY_MAX {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Check whether the pkey is currently allocated in the per-process bitmap.
///
/// Returns `Err(InvalidArgument)` if the pkey is not currently allocated
/// (which would indicate a double-free or a pkey from another process).
pub fn check_pkey_allocated(bitmap: u32, pkey: u32) -> Result<()> {
    if pkey >= PKEY_MAX {
        return Err(Error::InvalidArgument);
    }
    if (bitmap >> pkey) & 1 == 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Free the pkey bit in the per-process pkey bitmap.
///
/// Returns the updated bitmap with the pkey bit cleared.
pub fn free_pkey(bitmap: u32, pkey: u32) -> Result<u32> {
    if pkey >= PKEY_MAX {
        return Err(Error::InvalidArgument);
    }
    if (bitmap >> pkey) & 1 == 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(bitmap & !(1u32 << pkey))
}

/// Handle the `pkey_free` syscall.
///
/// Frees the protection key `pkey`, marking it available for future
/// allocations. The PKRU bits for this key are reset to grant full access
/// so that any memory still tagged with it is readable again.
///
/// Returns 0 on success, or an error.
pub fn sys_pkey_free(args: &PkeyFreeArgs) -> Result<i64> {
    validate_pkey_free_args(args)?;
    // Stub: real implementation would:
    // 1. Lock the per-mm pkey bitmap.
    // 2. Verify the pkey bit is set (not a double-free).
    // 3. Clear the bit in the bitmap.
    // 4. Reset the PKRU bits for this pkey to 0 (full access).
    // 5. Return 0.
    Err(Error::NotImplemented)
}

/// Reset the PKRU bits for a given pkey to zero (full access granted).
///
/// This is called after freeing a pkey to avoid stale access restrictions.
pub fn reset_pkey_pkru(pkru: u32, pkey: u32) -> u32 {
    if pkey >= PKEY_MAX {
        return pkru;
    }
    let shift = pkey * 2;
    let mask = 0x3u32 << shift;
    pkru & !mask
}

/// Count the number of currently allocated pkeys in a bitmap.
pub fn count_allocated_pkeys(bitmap: u32) -> u32 {
    // Pkey 0 is the default and is never in the allocation bitmap.
    (bitmap >> 1).count_ones()
}

/// Check whether all pkeys are currently allocated.
pub fn all_pkeys_allocated(bitmap: u32) -> bool {
    // Full bitmap: bits 1..15 all set.
    let all_bits = ((1u32 << PKEY_MAX) - 1) & !1;
    bitmap & all_bits == all_bits
}
