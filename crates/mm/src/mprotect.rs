// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory protection and advisory (`mprotect` / `madvise`) support.
//!
//! Provides POSIX-compatible `mprotect` for changing page-level
//! protection flags and `madvise` for hinting the kernel about
//! expected memory access patterns.
//!
//! # POSIX Reference
//!
//! - `mprotect(2)` — POSIX.1-2024, XSH `mprotect`
//! - `madvise(2)` — POSIX.1-2024, XSH `posix_madvise`

use oncrix_lib::{Error, Result};

use crate::addr::PAGE_SIZE;

// ── mprotect protection flags ────────────────────────────────────

/// No access allowed.
pub const PROT_NONE: u32 = 0x0;
/// Pages may be read.
pub const PROT_READ: u32 = 0x1;
/// Pages may be written.
pub const PROT_WRITE: u32 = 0x2;
/// Pages may be executed.
pub const PROT_EXEC: u32 = 0x4;

/// Bitmask of all valid protection flags.
const PROT_VALID_MASK: u32 = PROT_READ | PROT_WRITE | PROT_EXEC;

// ── ProtFlags ────────────────────────────────────────────────────

/// Memory protection flags for a virtual memory region.
///
/// Wraps a raw `u32` bitmask of `PROT_*` constants and provides
/// type-safe query methods. Use [`ProtFlags::from_raw`] to
/// construct from a user-supplied value after validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtFlags(u32);

impl Default for ProtFlags {
    /// Default protection is [`PROT_NONE`] (no access).
    fn default() -> Self {
        Self(PROT_NONE)
    }
}

impl ProtFlags {
    /// Create `ProtFlags` from a raw bitmask, validating that only
    /// known bits are set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if unknown bits are set.
    pub fn from_raw(raw: u32) -> Result<Self> {
        if raw & !PROT_VALID_MASK != 0 && raw != PROT_NONE {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Return the underlying `u32` bitmask.
    pub fn as_raw(self) -> u32 {
        self.0
    }

    /// Return `true` if the region is readable.
    pub fn is_readable(self) -> bool {
        self.0 & PROT_READ != 0
    }

    /// Return `true` if the region is writable.
    pub fn is_writable(self) -> bool {
        self.0 & PROT_WRITE != 0
    }

    /// Return `true` if the region is executable.
    pub fn is_executable(self) -> bool {
        self.0 & PROT_EXEC != 0
    }

    /// Return `true` if the raw value contains only valid flag
    /// bits (or is `PROT_NONE`).
    pub fn is_valid(self) -> bool {
        self.0 == PROT_NONE || self.0 & !PROT_VALID_MASK == 0
    }
}

// ── do_mprotect ──────────────────────────────────────────────────

/// Change memory protection for a range of pages.
///
/// # Arguments
///
/// - `addr` — Start of the region (must be page-aligned).
/// - `len` — Length in bytes (rounded up to page boundary).
/// - `prot` — New protection flags (`PROT_*` bitmask).
///
/// # Errors
///
/// - [`Error::InvalidArgument`] if `addr` is not page-aligned.
/// - [`Error::InvalidArgument`] if `len` is zero.
/// - [`Error::InvalidArgument`] if `prot` contains unknown bits.
/// - [`Error::NotImplemented`] (stub — awaiting AddressSpace
///   integration).
///
/// # POSIX Reference
///
/// See `mprotect(2)`: the address must be page-aligned and the
/// length is implicitly rounded up to the next page boundary.
pub fn do_mprotect(addr: u64, len: u64, prot: u32) -> Result<()> {
    // Address must be page-aligned.
    if addr % PAGE_SIZE as u64 != 0 {
        return Err(Error::InvalidArgument);
    }

    // Length must be non-zero.
    if len == 0 {
        return Err(Error::InvalidArgument);
    }

    // Validate protection flags.
    let _flags = ProtFlags::from_raw(prot)?;

    // Stub: full implementation will:
    //   1. Look up VMA(s) covering [addr, addr+len).
    //   2. Split VMAs at boundaries if needed.
    //   3. Update page table entries with new permissions.
    //   4. Flush TLB for affected pages.
    Err(Error::NotImplemented)
}

// ── madvise hint constants ───────────────────────────────────────

/// No special treatment — default readahead heuristics.
pub const MADV_NORMAL: i32 = 0;
/// Expect random page references — disable readahead.
pub const MADV_RANDOM: i32 = 1;
/// Expect sequential page references — aggressive readahead.
pub const MADV_SEQUENTIAL: i32 = 2;
/// Pages will be needed soon — initiate readahead.
pub const MADV_WILLNEED: i32 = 3;
/// Pages are not needed — may be freed by the kernel.
pub const MADV_DONTNEED: i32 = 4;
/// Pages may be freed when memory pressure occurs.
pub const MADV_FREE: i32 = 8;
/// Remove the pages entirely (shared/tmpfs mappings).
pub const MADV_REMOVE: i32 = 9;
/// Do not inherit this range across `fork`.
pub const MADV_DONTFORK: i32 = 10;
/// Undo `MADV_DONTFORK` — inherit across `fork`.
pub const MADV_DOFORK: i32 = 11;
/// Mark pages as candidates for Kernel Same-page Merging.
pub const MADV_MERGEABLE: i32 = 12;
/// Undo `MADV_MERGEABLE`.
pub const MADV_UNMERGEABLE: i32 = 13;
/// Enable Transparent Huge Pages for this range.
pub const MADV_HUGEPAGE: i32 = 14;
/// Disable Transparent Huge Pages for this range.
pub const MADV_NOHUGEPAGE: i32 = 15;
/// Hint that pages are "cold" and less likely to be accessed.
pub const MADV_COLD: i32 = 20;
/// Hint that pages should be reclaimed (paged out) soon.
pub const MADV_PAGEOUT: i32 = 21;

// ── MadviseHint ──────────────────────────────────────────────────

/// Parsed `madvise` hint value.
///
/// Provides a type-safe representation of the raw `advice`
/// integer passed to `madvise(2)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MadviseHint {
    /// No special treatment (default).
    Normal,
    /// Expect random access.
    Random,
    /// Expect sequential access.
    Sequential,
    /// Pages will be needed soon.
    WillNeed,
    /// Pages are not needed.
    DontNeed,
    /// Pages may be freed under pressure.
    Free,
    /// Remove pages entirely.
    Remove,
    /// Do not inherit across fork.
    DontFork,
    /// Inherit across fork (undo `DontFork`).
    DoFork,
    /// Enable KSM merging.
    Mergeable,
    /// Disable KSM merging.
    Unmergeable,
    /// Enable transparent huge pages.
    HugePage,
    /// Disable transparent huge pages.
    NoHugePage,
    /// Mark pages as cold.
    Cold,
    /// Reclaim pages soon.
    PageOut,
}

impl MadviseHint {
    /// Parse a raw `advice` integer into a [`MadviseHint`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the value does not
    /// correspond to a known `MADV_*` constant.
    pub fn from_raw(raw: i32) -> Result<Self> {
        match raw {
            MADV_NORMAL => Ok(Self::Normal),
            MADV_RANDOM => Ok(Self::Random),
            MADV_SEQUENTIAL => Ok(Self::Sequential),
            MADV_WILLNEED => Ok(Self::WillNeed),
            MADV_DONTNEED => Ok(Self::DontNeed),
            MADV_FREE => Ok(Self::Free),
            MADV_REMOVE => Ok(Self::Remove),
            MADV_DONTFORK => Ok(Self::DontFork),
            MADV_DOFORK => Ok(Self::DoFork),
            MADV_MERGEABLE => Ok(Self::Mergeable),
            MADV_UNMERGEABLE => Ok(Self::Unmergeable),
            MADV_HUGEPAGE => Ok(Self::HugePage),
            MADV_NOHUGEPAGE => Ok(Self::NoHugePage),
            MADV_COLD => Ok(Self::Cold),
            MADV_PAGEOUT => Ok(Self::PageOut),
            _ => Err(Error::InvalidArgument),
        }
    }
}

impl Default for MadviseHint {
    /// Default advice is [`MadviseHint::Normal`].
    fn default() -> Self {
        Self::Normal
    }
}

// ── do_madvise ───────────────────────────────────────────────────

/// Advise the kernel about expected memory access patterns.
///
/// # Arguments
///
/// - `addr` — Start of the region (must be page-aligned).
/// - `len` — Length in bytes (rounded up to page boundary).
/// - `advice` — Hint value (one of the `MADV_*` constants).
///
/// # Errors
///
/// - [`Error::InvalidArgument`] if `addr` is not page-aligned.
/// - [`Error::InvalidArgument`] if `len` is zero.
/// - [`Error::InvalidArgument`] if `advice` is not a known hint.
/// - [`Error::NotImplemented`] (stub — awaiting VM subsystem
///   integration).
///
/// # POSIX Reference
///
/// See `posix_madvise(3)` / `madvise(2)`.
pub fn do_madvise(addr: u64, len: u64, advice: i32) -> Result<()> {
    // Address must be page-aligned.
    if addr % PAGE_SIZE as u64 != 0 {
        return Err(Error::InvalidArgument);
    }

    // Length must be non-zero.
    if len == 0 {
        return Err(Error::InvalidArgument);
    }

    // Validate and parse the advice hint.
    let _hint = MadviseHint::from_raw(advice)?;

    // Stub: full implementation will:
    //   1. Look up VMA(s) covering [addr, addr+len).
    //   2. Apply hint-specific behaviour:
    //      - Normal/Random/Sequential: update readahead policy.
    //      - WillNeed: trigger page-in / readahead.
    //      - DontNeed: mark pages as reclaimable.
    //      - Free: lazily free pages on memory pressure.
    //      - DontFork/DoFork: update fork-inheritance flags.
    //      - HugePage/NoHugePage: update THP policy.
    //      - Cold/PageOut: move pages to inactive list.
    Err(Error::NotImplemented)
}
