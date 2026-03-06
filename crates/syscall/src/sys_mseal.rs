// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `mseal(2)` — seal memory mappings against modification.
//!
//! `mseal` was introduced in Linux 6.10 (syscall number 462 on x86_64).
//! It permanently marks one or more virtual memory areas as *sealed*,
//! preventing subsequent:
//! - `mprotect(2)` / `pkey_mprotect(2)` — changing protection bits
//! - `munmap(2)` — unmapping
//! - `mremap(2)` — remapping (old or new range checked)
//! - Destructive `madvise(2)` — `MADV_DONTNEED`, `MADV_FREE`, `MADV_REMOVE`
//!
//! Seals are inherited across `fork(2)` and cannot be removed once set.
//!
//! # Syscall signature
//!
//! ```text
//! int mseal(void *addr, size_t len, unsigned long flags);
//! ```
//!
//! - `addr`  — Page-aligned start of the range.
//! - `len`   — Page-aligned, non-zero length.
//! - `flags` — Reserved; must be 0.
//!
//! # Interaction with pkey_mprotect
//!
//! `pkey_mprotect` is blocked on sealed ranges, same as `mprotect`.
//!
//! # Linux reference
//!
//! `mm/mseal.c`, `include/linux/mm.h` (`VM_SEALED` bit).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// x86_64 Linux ABI syscall number for `mseal`.
pub const SYS_MSEAL: u64 = 462;

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Page-offset mask.
const PAGE_MASK: u64 = PAGE_SIZE - 1;

/// Canonical user-space address ceiling (x86_64 lower half).
const USER_ADDR_LIMIT: u64 = 0x0000_8000_0000_0000;

/// Maximum number of sealed regions stored per process seal map.
pub const MSEAL_MAX_REGIONS: usize = 512;

// ---------------------------------------------------------------------------
// `madvise` advice values blocked on sealed ranges
// ---------------------------------------------------------------------------

/// `MADV_DONTNEED` (8) — free anonymous pages backing the range.
/// Also covers `MADV_FREE` which equals 8 on x86_64 Linux.
const MADV_DONTNEED: i32 = 8;
/// `MADV_REMOVE` (9) — remove backing storage from a file/shmem mapping.
const MADV_REMOVE: i32 = 9;

/// Return `true` if `advice` is a destructive `madvise` operation that is
/// blocked on sealed memory.
///
/// Blocked advice values: `MADV_DONTNEED` (8, which also covers `MADV_FREE`
/// on x86_64 where both share value 8) and `MADV_REMOVE` (9).
pub fn is_destructive_advice(advice: i32) -> bool {
    advice == MADV_DONTNEED || advice == MADV_REMOVE
}

// ---------------------------------------------------------------------------
// SealedRegion — one sealed address interval
// ---------------------------------------------------------------------------

/// A sealed virtual address interval `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedRegion {
    /// Inclusive start (page-aligned).
    pub start: u64,
    /// Exclusive end (page-aligned).
    pub end: u64,
}

impl SealedRegion {
    /// Construct a sealed region.
    pub const fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    /// Size in bytes.
    pub const fn len(&self) -> u64 {
        self.end - self.start
    }

    /// Return `true` if the region spans zero bytes.
    pub const fn is_empty(&self) -> bool {
        self.start >= self.end
    }

    /// Return `true` if `[addr, addr+len)` overlaps this region.
    pub const fn overlaps(&self, addr: u64, len: u64) -> bool {
        if len == 0 {
            return false;
        }
        let end = addr.saturating_add(len);
        addr < self.end && end > self.start
    }

    /// Return `true` if this region and `other` are adjacent or overlapping.
    pub const fn can_merge(&self, other: &SealedRegion) -> bool {
        self.end >= other.start && other.end >= self.start
    }

    /// Merge `other` into this region (returns the union).
    pub const fn merge(&self, other: &SealedRegion) -> SealedRegion {
        let start = if self.start < other.start {
            self.start
        } else {
            other.start
        };
        let end = if self.end > other.end {
            self.end
        } else {
            other.end
        };
        SealedRegion { start, end }
    }
}

// ---------------------------------------------------------------------------
// SealMap — per-process sealed region collection
// ---------------------------------------------------------------------------

/// Per-process collection of sealed address regions.
///
/// Regions are stored unsorted in a flat array.  Adjacent or overlapping
/// regions are coalesced on insertion.
pub struct SealMap {
    regions: [Option<SealedRegion>; MSEAL_MAX_REGIONS],
    count: usize,
}

impl SealMap {
    /// Create an empty seal map.
    pub const fn new() -> Self {
        Self {
            regions: [const { None }; MSEAL_MAX_REGIONS],
            count: 0,
        }
    }

    /// Number of active sealed regions.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if there are no sealed regions.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return `true` if `[addr, addr+len)` overlaps any sealed region.
    pub fn is_sealed(&self, addr: u64, len: u64) -> bool {
        for i in 0..self.count {
            if let Some(r) = &self.regions[i] {
                if r.overlaps(addr, len) {
                    return true;
                }
            }
        }
        false
    }

    /// Seal the range `[addr, addr+len)`.
    ///
    /// Adjacent or overlapping existing sealed regions are coalesced into
    /// the new region.
    ///
    /// # Errors
    ///
    /// * [`Error::InvalidArgument`] — `addr + len` overflows.
    /// * [`Error::OutOfMemory`]     — Region table is full.
    pub fn seal(&mut self, addr: u64, len: u64) -> Result<()> {
        let end = addr.checked_add(len).ok_or(Error::InvalidArgument)?;
        let mut merged = SealedRegion::new(addr, end);

        // Mark existing regions that overlap or are adjacent for removal.
        let mut to_remove = [false; MSEAL_MAX_REGIONS];
        for i in 0..self.count {
            if let Some(r) = &self.regions[i] {
                if merged.can_merge(r) {
                    merged = merged.merge(r);
                    to_remove[i] = true;
                }
            }
        }

        // Remove marked regions (compact from the end to preserve indices).
        for i in (0..self.count).rev() {
            if to_remove[i] {
                if i < self.count - 1 {
                    self.regions[i] = self.regions[self.count - 1].take();
                } else {
                    self.regions[i] = None;
                }
                self.count -= 1;
            }
        }

        // Insert the merged region.
        if self.count >= MSEAL_MAX_REGIONS {
            return Err(Error::OutOfMemory);
        }
        self.regions[self.count] = Some(merged);
        self.count += 1;
        Ok(())
    }

    /// Iterate over active sealed regions.
    pub fn iter_regions(&self) -> impl Iterator<Item = &SealedRegion> {
        self.regions[..self.count].iter().filter_map(|r| r.as_ref())
    }
}

impl Default for SealMap {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Argument validation
// ---------------------------------------------------------------------------

/// Validate `mseal(2)` arguments.
///
/// # Checks
///
/// - `flags` is 0.
/// - `addr` is page-aligned.
/// - `len` is non-zero and page-aligned.
/// - `addr + len` does not overflow.
/// - `addr + len` is within the user-space canonical range.
pub fn validate_mseal_args(addr: u64, len: u64, flags: u64) -> Result<()> {
    if flags != 0 {
        return Err(Error::InvalidArgument);
    }
    if addr & PAGE_MASK != 0 {
        return Err(Error::InvalidArgument);
    }
    if len == 0 || len & PAGE_MASK != 0 {
        return Err(Error::InvalidArgument);
    }
    let end = addr.checked_add(len).ok_or(Error::InvalidArgument)?;
    if end > USER_ADDR_LIMIT {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Enforcement helpers
// ---------------------------------------------------------------------------

/// Check whether `mprotect` / `pkey_mprotect` is permitted.
///
/// Returns `PermissionDenied` if the range overlaps a sealed region.
pub fn check_mprotect(map: &SealMap, addr: u64, len: u64) -> Result<()> {
    if map.is_sealed(addr, len) {
        return Err(Error::PermissionDenied);
    }
    Ok(())
}

/// Check whether `munmap` is permitted.
///
/// Returns `PermissionDenied` if the range overlaps a sealed region.
pub fn check_munmap(map: &SealMap, addr: u64, len: u64) -> Result<()> {
    if map.is_sealed(addr, len) {
        return Err(Error::PermissionDenied);
    }
    Ok(())
}

/// Check whether `mremap` is permitted.
///
/// Both the old range and the new range (when `new_addr != 0`) are checked.
/// Returns `PermissionDenied` if either overlaps a sealed region.
pub fn check_mremap(
    map: &SealMap,
    old_addr: u64,
    old_len: u64,
    new_addr: u64,
    new_len: u64,
) -> Result<()> {
    if map.is_sealed(old_addr, old_len) {
        return Err(Error::PermissionDenied);
    }
    if new_addr != 0 && map.is_sealed(new_addr, new_len) {
        return Err(Error::PermissionDenied);
    }
    Ok(())
}

/// Check whether an `madvise` call is permitted.
///
/// Destructive advice values (`MADV_DONTNEED`, `MADV_FREE`, `MADV_REMOVE`)
/// are blocked on sealed ranges.  Non-destructive advice is always allowed.
pub fn check_madvise(map: &SealMap, addr: u64, len: u64, advice: i32) -> Result<()> {
    if is_destructive_advice(advice) && map.is_sealed(addr, len) {
        return Err(Error::PermissionDenied);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Fork inheritance
// ---------------------------------------------------------------------------

/// Clone the seal map for a child process after `fork(2)`.
///
/// All sealed regions are preserved in the child.  Seals cannot be dropped.
pub fn fork_seal_map(parent: &SealMap) -> SealMap {
    let mut child = SealMap::new();
    for region in parent.iter_regions() {
        // Safe to ignore errors here: the parent map was already validated.
        let _ = child.seal(region.start, region.end - region.start);
    }
    child
}

// ---------------------------------------------------------------------------
// sys_mseal — primary handler
// ---------------------------------------------------------------------------

/// `mseal(2)` syscall handler.
///
/// Seals the virtual address range `[addr, addr+len)` against modification.
///
/// # Arguments
///
/// * `map`   — Per-process seal map (mutable).
/// * `addr`  — Page-aligned range start.
/// * `len`   — Page-aligned, non-zero length.
/// * `flags` — Must be 0.
///
/// # Returns
///
/// `0` on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Misaligned address/length, non-zero flags,
///   overflow, or kernel-space address.
/// * [`Error::OutOfMemory`]     — Seal map is full.
pub fn sys_mseal(map: &mut SealMap, addr: u64, len: u64, flags: u64) -> Result<i32> {
    validate_mseal_args(addr, len, flags)?;
    map.seal(addr, len)?;
    Ok(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- SealedRegion ---

    #[test]
    fn region_overlaps() {
        let r = SealedRegion::new(0x1000, 0x3000);
        assert!(r.overlaps(0x1000, 0x1000));
        assert!(r.overlaps(0x0800, 0x1000)); // left partial
        assert!(r.overlaps(0x2800, 0x1000)); // right partial
        assert!(!r.overlaps(0x0000, 0x1000)); // before
        assert!(!r.overlaps(0x3000, 0x1000)); // after
        assert!(!r.overlaps(0x2000, 0)); // zero len
    }

    #[test]
    fn region_merge() {
        let a = SealedRegion::new(0x1000, 0x3000);
        let b = SealedRegion::new(0x2000, 0x5000);
        let m = a.merge(&b);
        assert_eq!(m.start, 0x1000);
        assert_eq!(m.end, 0x5000);
    }

    #[test]
    fn region_can_merge_adjacent() {
        let a = SealedRegion::new(0x1000, 0x2000);
        let b = SealedRegion::new(0x2000, 0x3000);
        assert!(a.can_merge(&b));
        assert!(b.can_merge(&a));
    }

    // --- validate_mseal_args ---

    #[test]
    fn validate_ok() {
        assert_eq!(validate_mseal_args(0x1000, 0x1000, 0), Ok(()));
    }

    #[test]
    fn validate_nonzero_flags() {
        assert_eq!(
            validate_mseal_args(0x1000, 0x1000, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_misaligned_addr() {
        assert_eq!(
            validate_mseal_args(0x1001, 0x1000, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_zero_len() {
        assert_eq!(
            validate_mseal_args(0x1000, 0, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_misaligned_len() {
        assert_eq!(
            validate_mseal_args(0x1000, 0x1001, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_overflow() {
        assert_eq!(
            validate_mseal_args(u64::MAX - 0xFFF, 0x2000, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_kernel_space() {
        assert_eq!(
            validate_mseal_args(0x0000_7FFF_FFFF_F000, 0x2000, 0),
            Err(Error::InvalidArgument)
        );
    }

    // --- SealMap ---

    #[test]
    fn seal_and_query() {
        let mut m = SealMap::new();
        sys_mseal(&mut m, 0x1000, 0x2000, 0).unwrap();
        assert!(m.is_sealed(0x1000, 0x1000));
        assert!(m.is_sealed(0x2500, 0x500));
        assert!(!m.is_sealed(0x3000, 0x1000));
        assert!(!m.is_sealed(0x0000, 0x1000));
    }

    #[test]
    fn seal_non_overlapping() {
        let mut m = SealMap::new();
        sys_mseal(&mut m, 0x1000, 0x1000, 0).unwrap();
        sys_mseal(&mut m, 0x5000, 0x1000, 0).unwrap();
        assert_eq!(m.len(), 2);
        assert!(m.is_sealed(0x1000, 0x1000));
        assert!(m.is_sealed(0x5000, 0x1000));
    }

    #[test]
    fn seal_overlapping_coalesces() {
        let mut m = SealMap::new();
        sys_mseal(&mut m, 0x1000, 0x2000, 0).unwrap();
        sys_mseal(&mut m, 0x2000, 0x2000, 0).unwrap();
        assert_eq!(m.len(), 1);
        assert!(m.is_sealed(0x1000, 0x3000));
    }

    #[test]
    fn seal_adjacent_coalesces() {
        let mut m = SealMap::new();
        sys_mseal(&mut m, 0x1000, 0x1000, 0).unwrap();
        sys_mseal(&mut m, 0x2000, 0x1000, 0).unwrap();
        assert_eq!(m.len(), 1);
    }

    // --- Enforcement checks ---

    #[test]
    fn mprotect_blocked_on_sealed() {
        let mut m = SealMap::new();
        sys_mseal(&mut m, 0x1000, 0x1000, 0).unwrap();
        assert_eq!(
            check_mprotect(&m, 0x1000, 0x1000),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn mprotect_allowed_outside() {
        let mut m = SealMap::new();
        sys_mseal(&mut m, 0x1000, 0x1000, 0).unwrap();
        assert_eq!(check_mprotect(&m, 0x2000, 0x1000), Ok(()));
    }

    #[test]
    fn munmap_blocked_on_sealed() {
        let mut m = SealMap::new();
        sys_mseal(&mut m, 0x4000, 0x2000, 0).unwrap();
        assert_eq!(
            check_munmap(&m, 0x4500, 0x500),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn mremap_old_range_blocked() {
        let mut m = SealMap::new();
        sys_mseal(&mut m, 0x1000, 0x1000, 0).unwrap();
        assert_eq!(
            check_mremap(&m, 0x1000, 0x1000, 0, 0),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn mremap_new_range_blocked() {
        let mut m = SealMap::new();
        sys_mseal(&mut m, 0x5000, 0x1000, 0).unwrap();
        assert_eq!(
            check_mremap(&m, 0x2000, 0x1000, 0x5000, 0x1000),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn mremap_new_addr_zero_skips_new_range_check() {
        let mut m = SealMap::new();
        sys_mseal(&mut m, 0x5000, 0x1000, 0).unwrap();
        // new_addr == 0 → kernel picks the address; skip the check.
        assert_eq!(check_mremap(&m, 0x2000, 0x1000, 0, 0x1000), Ok(()));
    }

    #[test]
    fn madvise_dontneed_blocked() {
        let mut m = SealMap::new();
        sys_mseal(&mut m, 0x1000, 0x1000, 0).unwrap();
        assert_eq!(
            check_madvise(&m, 0x1000, 0x1000, MADV_DONTNEED),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn madvise_willneed_allowed_on_sealed() {
        let mut m = SealMap::new();
        sys_mseal(&mut m, 0x1000, 0x1000, 0).unwrap();
        let madv_willneed = 3i32;
        assert_eq!(check_madvise(&m, 0x1000, 0x1000, madv_willneed), Ok(()));
    }

    // --- Fork inheritance ---

    #[test]
    fn fork_inherits_all_seals() {
        let mut parent = SealMap::new();
        sys_mseal(&mut parent, 0x1000, 0x2000, 0).unwrap();
        sys_mseal(&mut parent, 0x8000, 0x1000, 0).unwrap();
        let child = fork_seal_map(&parent);
        assert!(child.is_sealed(0x1000, 0x2000));
        assert!(child.is_sealed(0x8000, 0x1000));
        assert!(!child.is_sealed(0x5000, 0x1000));
    }

    // --- sys_mseal entry point ---

    #[test]
    fn sys_mseal_success_returns_zero() {
        let mut m = SealMap::new();
        assert_eq!(sys_mseal(&mut m, 0x1000, 0x1000, 0).unwrap(), 0);
    }

    #[test]
    fn sys_mseal_bad_args_propagates_error() {
        let mut m = SealMap::new();
        assert_eq!(
            sys_mseal(&mut m, 0x1001, 0x1000, 0),
            Err(Error::InvalidArgument)
        );
    }
}
