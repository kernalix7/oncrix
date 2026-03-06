// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `mseal(2)` — memory sealing.
//!
//! `mseal` prevents a set of virtual memory areas (VMAs) from being modified
//! by `mprotect`, `munmap`, `mremap`, and `madvise`. Once a range is sealed
//! it cannot be unsealed. Sealing is preserved across `fork(2)`.
//!
//! This is a Linux 6.10+ syscall designed primarily to protect critical
//! read-only mappings (e.g. `ld.so`, libc text segments) from being remapped
//! by an attacker who has achieved arbitrary-write-primitive.
//!
//! # Syscall signature
//!
//! ```text
//! int mseal(void *addr, size_t len, unsigned long flags);
//! ```
//!
//! - `addr`  — Start of the virtual address range (page-aligned).
//! - `len`   — Length of the range in bytes (page-aligned).
//! - `flags` — Reserved, must be 0.
//!
//! # Seal semantics
//!
//! Once sealed, the following operations on *any overlapping VMA* fail with
//! `EPERM`:
//! - `mprotect(2)` / `pkey_mprotect(2)`
//! - `munmap(2)`
//! - `mremap(2)` (both old and new range checked)
//! - `madvise(2)` with destructive advice (`MADV_DONTNEED`, `MADV_FREE`, etc.)
//!
//! Non-destructive `madvise` calls (e.g. `MADV_WILLNEED`) are still allowed.
//!
//! # References
//!
//! - Linux: `mm/mseal.c`, `include/linux/mm.h` (`VM_SEALED` flag)
//! - Linux syscall number x86_64: 462

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Page size (4 KiB).
pub const PAGE_SIZE: u64 = 4096;

/// Page-offset mask.
const PAGE_MASK: u64 = PAGE_SIZE - 1;

/// Upper bound of user-space canonical addresses (x86_64 lower half).
const USER_SPACE_END: u64 = 0x0000_8000_0000_0000;

/// Maximum number of sealed ranges trackable per process in this stub.
pub const MSEAL_MAX_RANGES: usize = 256;

/// Syscall number for `mseal` (x86_64 Linux ABI).
pub const SYS_MSEAL: u64 = 462;

/// `madvise` advice values considered destructive (blocked on sealed ranges).
const DESTRUCTIVE_MADVISE: &[i32] = &[
    8,  // MADV_DONTNEED
    9,  // MADV_FREE
    12, // MADV_REMOVE
    13, // MADV_DONTFORK
    15, // MADV_DOFORK
];

// ---------------------------------------------------------------------------
// SealedRange — a single sealed address interval
// ---------------------------------------------------------------------------

/// A sealed virtual address range `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedRange {
    /// Inclusive start (page-aligned).
    pub start: u64,
    /// Exclusive end (page-aligned).
    pub end: u64,
}

impl SealedRange {
    /// Construct a sealed range.
    pub const fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    /// Return `true` if `[addr, addr+len)` overlaps this sealed range.
    pub const fn overlaps(&self, addr: u64, len: u64) -> bool {
        if len == 0 {
            return false;
        }
        let end = addr.saturating_add(len);
        addr < self.end && end > self.start
    }

    /// Return `true` if this range fully contains `[addr, addr+len)`.
    pub const fn contains(&self, addr: u64, len: u64) -> bool {
        if len == 0 {
            return true;
        }
        let end = addr.saturating_add(len);
        addr >= self.start && end <= self.end
    }
}

// ---------------------------------------------------------------------------
// SealMap — per-process set of sealed ranges
// ---------------------------------------------------------------------------

/// Per-process collection of sealed ranges.
///
/// Ranges are stored in a fixed-size array sorted by start address.
/// Overlapping and adjacent ranges are coalesced during insertion.
pub struct SealMap {
    ranges: [Option<SealedRange>; MSEAL_MAX_RANGES],
    count: usize,
}

impl SealMap {
    /// Create an empty seal map.
    pub const fn new() -> Self {
        Self {
            ranges: [const { None }; MSEAL_MAX_RANGES],
            count: 0,
        }
    }

    /// Return the number of sealed ranges.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if there are no sealed ranges.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return `true` if `[addr, addr+len)` overlaps any sealed range.
    pub fn is_sealed(&self, addr: u64, len: u64) -> bool {
        for i in 0..self.count {
            if let Some(r) = &self.ranges[i] {
                if r.overlaps(addr, len) {
                    return true;
                }
            }
        }
        false
    }

    /// Seal the range `[addr, addr+len)`.
    ///
    /// If the range overlaps or is adjacent to existing sealed ranges,
    /// they are coalesced. Returns `OutOfMemory` if the map is full
    /// and no coalescing is possible.
    pub fn seal(&mut self, addr: u64, len: u64) -> Result<()> {
        let end = addr.checked_add(len).ok_or(Error::InvalidArgument)?;
        let new = SealedRange::new(addr, end);

        // Find ranges that overlap or are adjacent and merge.
        let mut merged = new;
        let mut to_remove = [false; MSEAL_MAX_RANGES];

        for i in 0..self.count {
            if let Some(r) = &self.ranges[i] {
                // Adjacent: r.end == merged.start or merged.end == r.start
                let adjacent = r.end == merged.start || merged.end == r.start;
                let overlapping = r.overlaps(merged.start, merged.end - merged.start);
                if adjacent || overlapping {
                    merged.start = merged.start.min(r.start);
                    merged.end = merged.end.max(r.end);
                    to_remove[i] = true;
                }
            }
        }

        // Remove merged ranges.
        for i in (0..self.count).rev() {
            if to_remove[i] {
                self.ranges[i] = None;
                // Compact: move last to i.
                if i < self.count - 1 {
                    self.ranges[i] = self.ranges[self.count - 1].take();
                }
                self.count -= 1;
            }
        }

        // Insert the merged range.
        if self.count >= MSEAL_MAX_RANGES {
            return Err(Error::OutOfMemory);
        }
        self.ranges[self.count] = Some(merged);
        self.count += 1;
        Ok(())
    }

    /// Return an iterator-like slice of active ranges.
    pub fn active_ranges(&self) -> impl Iterator<Item = &SealedRange> {
        self.ranges[..self.count].iter().filter_map(|r| r.as_ref())
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

/// Validate `mseal` syscall arguments.
///
/// # Checks
///
/// - `addr` is page-aligned.
/// - `len` is non-zero and page-aligned.
/// - `addr + len` does not overflow.
/// - `addr + len` stays within user-space canonical range.
/// - `flags` is zero.
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
    if end > USER_SPACE_END {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// do_mseal
// ---------------------------------------------------------------------------

/// Core logic for `mseal(2)`.
///
/// Validates arguments, then records the sealed range in `map`.
///
/// # Arguments
///
/// - `map`   — Per-process seal map (mutable).
/// - `addr`  — Page-aligned start of the range to seal.
/// - `len`   — Page-aligned length of the range.
/// - `flags` — Must be 0.
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — Misaligned address/length, non-zero flags,
///   address overflow, or kernel-space address.
/// - [`Error::OutOfMemory`]     — Internal seal map is full.
pub fn do_mseal(map: &mut SealMap, addr: u64, len: u64, flags: u64) -> Result<()> {
    validate_mseal_args(addr, len, flags)?;
    map.seal(addr, len)
}

// ---------------------------------------------------------------------------
// Seal enforcement helpers
// ---------------------------------------------------------------------------

/// Check whether an `mprotect` / `pkey_mprotect` operation is allowed.
///
/// Returns `Err(PermissionDenied)` if `[addr, addr+len)` overlaps a sealed
/// range.
pub fn check_mprotect(map: &SealMap, addr: u64, len: u64) -> Result<()> {
    if map.is_sealed(addr, len) {
        return Err(Error::PermissionDenied);
    }
    Ok(())
}

/// Check whether a `munmap` operation is allowed.
///
/// Returns `Err(PermissionDenied)` if `[addr, addr+len)` overlaps a sealed
/// range.
pub fn check_munmap(map: &SealMap, addr: u64, len: u64) -> Result<()> {
    if map.is_sealed(addr, len) {
        return Err(Error::PermissionDenied);
    }
    Ok(())
}

/// Check whether an `mremap` operation is allowed.
///
/// Both the old range `[old_addr, old_addr+old_len)` and the new address
/// `new_addr` (if non-zero, i.e. `MREMAP_FIXED`) are checked.
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

/// Check whether an `madvise` operation is allowed.
///
/// Destructive advice values are blocked on sealed ranges. Non-destructive
/// advice (e.g. `MADV_WILLNEED`) is always allowed.
pub fn check_madvise(map: &SealMap, addr: u64, len: u64, advice: i32) -> Result<()> {
    let destructive = DESTRUCTIVE_MADVISE.contains(&advice);
    if destructive && map.is_sealed(addr, len) {
        return Err(Error::PermissionDenied);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Fork inheritance
// ---------------------------------------------------------------------------

/// Clone a `SealMap` for a forked child process.
///
/// All sealed ranges are inherited — seals cannot be dropped after fork.
pub fn fork_seal_map(parent: &SealMap) -> SealMap {
    let mut child = SealMap::new();
    for r in parent.active_ranges() {
        // Capacity was already validated when the parent sealed ranges.
        // Errors here would indicate a bug in the parent map.
        let _ = child.seal(r.start, r.end - r.start);
    }
    child
}

// ---------------------------------------------------------------------------
// Syscall entry point
// ---------------------------------------------------------------------------

/// Process a raw `mseal` syscall.
///
/// # Arguments
///
/// - `map`   — Per-process seal map.
/// - `addr`  — Raw `addr` register value.
/// - `len`   — Raw `len` register value.
/// - `flags` — Raw `flags` register value.
///
/// # Returns
///
/// 0 on success.
pub fn sys_mseal(map: &mut SealMap, addr: u64, len: u64, flags: u64) -> Result<i32> {
    do_mseal(map, addr, len, flags)?;
    Ok(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- SealedRange ---

    #[test]
    fn sealed_range_overlaps() {
        let r = SealedRange::new(0x1000, 0x3000);
        // Fully inside.
        assert!(r.overlaps(0x1000, 0x2000));
        // Partial left overlap.
        assert!(r.overlaps(0x0800, 0x1000));
        // Partial right overlap.
        assert!(r.overlaps(0x2800, 0x1000));
        // Fully outside before.
        assert!(!r.overlaps(0x0000, 0x1000));
        // Fully outside after.
        assert!(!r.overlaps(0x3000, 0x1000));
        // Zero length.
        assert!(!r.overlaps(0x2000, 0));
    }

    #[test]
    fn sealed_range_contains() {
        let r = SealedRange::new(0x1000, 0x4000);
        assert!(r.contains(0x1000, 0x3000));
        assert!(r.contains(0x2000, 0x1000));
        assert!(!r.contains(0x0800, 0x1000)); // starts before
        assert!(!r.contains(0x3000, 0x2000)); // ends after
    }

    // --- validate_mseal_args ---

    #[test]
    fn validate_ok() {
        assert_eq!(validate_mseal_args(0x1000, 0x1000, 0), Ok(()));
    }

    #[test]
    fn validate_flags_nonzero() {
        assert_eq!(
            validate_mseal_args(0x1000, 0x1000, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_addr_misaligned() {
        assert_eq!(
            validate_mseal_args(0x1001, 0x1000, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_len_zero() {
        assert_eq!(
            validate_mseal_args(0x1000, 0, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_len_misaligned() {
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

    // --- SealMap basic operations ---

    #[test]
    fn seal_and_query() {
        let mut m = SealMap::new();
        do_mseal(&mut m, 0x1000, 0x2000, 0).unwrap();
        assert!(m.is_sealed(0x1000, 0x1000));
        assert!(m.is_sealed(0x2000, 0x1000));
        assert!(!m.is_sealed(0x3000, 0x1000));
        assert!(!m.is_sealed(0x0000, 0x1000));
    }

    #[test]
    fn seal_non_overlapping_ranges() {
        let mut m = SealMap::new();
        do_mseal(&mut m, 0x1000, 0x1000, 0).unwrap();
        do_mseal(&mut m, 0x5000, 0x1000, 0).unwrap();
        assert!(m.is_sealed(0x1000, 0x1000));
        assert!(m.is_sealed(0x5000, 0x1000));
        assert!(!m.is_sealed(0x2000, 0x3000));
    }

    #[test]
    fn seal_overlapping_coalesced() {
        let mut m = SealMap::new();
        do_mseal(&mut m, 0x1000, 0x2000, 0).unwrap();
        do_mseal(&mut m, 0x2000, 0x2000, 0).unwrap(); // overlaps at 0x2000-0x3000
        // After coalescing should be [0x1000, 0x4000).
        assert_eq!(m.len(), 1);
        assert!(m.is_sealed(0x1000, 0x3000));
    }

    #[test]
    fn seal_adjacent_coalesced() {
        let mut m = SealMap::new();
        do_mseal(&mut m, 0x1000, 0x1000, 0).unwrap(); // [0x1000, 0x2000)
        do_mseal(&mut m, 0x2000, 0x1000, 0).unwrap(); // [0x2000, 0x3000)
        assert_eq!(m.len(), 1);
        assert!(m.is_sealed(0x1000, 0x2000));
    }

    // --- check_mprotect ---

    #[test]
    fn mprotect_blocked_on_sealed() {
        let mut m = SealMap::new();
        do_mseal(&mut m, 0x1000, 0x1000, 0).unwrap();
        assert_eq!(
            check_mprotect(&m, 0x1000, 0x1000),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn mprotect_allowed_outside_sealed() {
        let mut m = SealMap::new();
        do_mseal(&mut m, 0x1000, 0x1000, 0).unwrap();
        assert_eq!(check_mprotect(&m, 0x2000, 0x1000), Ok(()));
    }

    // --- check_munmap ---

    #[test]
    fn munmap_blocked_on_sealed() {
        let mut m = SealMap::new();
        do_mseal(&mut m, 0x4000, 0x2000, 0).unwrap();
        assert_eq!(
            check_munmap(&m, 0x4000, 0x2000),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn munmap_allowed_outside_sealed() {
        let mut m = SealMap::new();
        do_mseal(&mut m, 0x4000, 0x2000, 0).unwrap();
        assert_eq!(check_munmap(&m, 0x8000, 0x1000), Ok(()));
    }

    // --- check_mremap ---

    #[test]
    fn mremap_old_range_blocked() {
        let mut m = SealMap::new();
        do_mseal(&mut m, 0x1000, 0x1000, 0).unwrap();
        assert_eq!(
            check_mremap(&m, 0x1000, 0x1000, 0, 0),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn mremap_new_range_blocked() {
        let mut m = SealMap::new();
        do_mseal(&mut m, 0x5000, 0x1000, 0).unwrap();
        // Old range is safe, new target overlaps sealed.
        assert_eq!(
            check_mremap(&m, 0x2000, 0x1000, 0x5000, 0x1000),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn mremap_new_addr_zero_skipped() {
        let mut m = SealMap::new();
        do_mseal(&mut m, 0x5000, 0x1000, 0).unwrap();
        // new_addr == 0 means kernel chooses; skip the new-range check.
        assert_eq!(check_mremap(&m, 0x2000, 0x1000, 0, 0x1000), Ok(()));
    }

    // --- check_madvise ---

    #[test]
    fn madvise_dontneed_blocked_on_sealed() {
        let mut m = SealMap::new();
        do_mseal(&mut m, 0x1000, 0x1000, 0).unwrap();
        let madv_dontneed = 8i32;
        assert_eq!(
            check_madvise(&m, 0x1000, 0x1000, madv_dontneed),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn madvise_willneed_allowed_on_sealed() {
        let mut m = SealMap::new();
        do_mseal(&mut m, 0x1000, 0x1000, 0).unwrap();
        let madv_willneed = 3i32; // non-destructive
        assert_eq!(check_madvise(&m, 0x1000, 0x1000, madv_willneed), Ok(()));
    }

    #[test]
    fn madvise_dontneed_allowed_outside_sealed() {
        let mut m = SealMap::new();
        do_mseal(&mut m, 0x1000, 0x1000, 0).unwrap();
        let madv_dontneed = 8i32;
        assert_eq!(check_madvise(&m, 0x2000, 0x1000, madv_dontneed), Ok(()));
    }

    // --- Fork inheritance ---

    #[test]
    fn fork_inherits_seals() {
        let mut parent = SealMap::new();
        do_mseal(&mut parent, 0x1000, 0x2000, 0).unwrap();
        do_mseal(&mut parent, 0x8000, 0x1000, 0).unwrap();

        let child = fork_seal_map(&parent);
        assert!(child.is_sealed(0x1000, 0x2000));
        assert!(child.is_sealed(0x8000, 0x1000));
        assert!(!child.is_sealed(0x4000, 0x1000));
    }

    // --- Syscall entry ---

    #[test]
    fn sys_mseal_success() {
        let mut m = SealMap::new();
        assert_eq!(sys_mseal(&mut m, 0x1000, 0x1000, 0).unwrap(), 0);
    }

    #[test]
    fn sys_mseal_bad_args() {
        let mut m = SealMap::new();
        assert_eq!(
            sys_mseal(&mut m, 0x1001, 0x1000, 0),
            Err(Error::InvalidArgument)
        );
    }
}
