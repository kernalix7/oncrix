// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `mremap` syscall handler.
//!
//! Implements `mremap(2)` per Linux ABI.
//! `mremap` resizes or relocates an existing memory mapping.
//! The mapping may be grown in place, shrunk in place, or moved
//! to a new address when `MREMAP_MAYMOVE` is set.
//!
//! # References
//!
//! - Linux man pages: `mremap(2)`
//! - Linux mm/mremap.c

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Page size
// ---------------------------------------------------------------------------

/// Default system page size (4 KiB).
pub const PAGE_SIZE: u64 = 4096;

/// Page offset mask.
const PAGE_MASK: u64 = PAGE_SIZE - 1;

// ---------------------------------------------------------------------------
// Mremap flags
// ---------------------------------------------------------------------------

/// Allow the kernel to move the mapping to a different address.
pub const MREMAP_MAYMOVE: u32 = 1;
/// Move the mapping to exactly `new_address` (requires MREMAP_MAYMOVE).
pub const MREMAP_FIXED: u32 = 2;
/// Don't unmap the old mapping when using MREMAP_FIXED | MREMAP_MAYMOVE.
pub const MREMAP_DONTUNMAP: u32 = 4;

/// Mask of all recognised mremap flags.
const MREMAP_VALID_MASK: u32 = MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP;

// ---------------------------------------------------------------------------
// MremapArgs — parameter bundle
// ---------------------------------------------------------------------------

/// Arguments for `mremap`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MremapArgs {
    /// Start address of the existing mapping (must be page-aligned).
    pub old_addr: u64,
    /// Size of the existing mapping in bytes.
    pub old_size: u64,
    /// Desired new size in bytes.
    pub new_size: u64,
    /// Flags controlling the operation (`MREMAP_*`).
    pub flags: u32,
    /// New address for the mapping (only used with `MREMAP_FIXED`).
    pub new_addr: u64,
}

impl MremapArgs {
    /// Validate all `mremap` arguments.
    ///
    /// Returns `Err(InvalidArgument)` when:
    /// - `old_addr` is not page-aligned.
    /// - `old_size` or `new_size` is zero.
    /// - Unknown flags are set.
    /// - `MREMAP_FIXED` is set without `MREMAP_MAYMOVE`.
    /// - `MREMAP_FIXED` is set and `new_addr` is not page-aligned.
    /// - `MREMAP_DONTUNMAP` is set without `MREMAP_MAYMOVE`.
    /// - The old mapping would overflow (old_addr + old_size overflow).
    pub fn validate(&self) -> Result<()> {
        if self.old_addr & PAGE_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.old_size == 0 || self.new_size == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.flags & !MREMAP_VALID_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.flags & MREMAP_FIXED != 0 && self.flags & MREMAP_MAYMOVE == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.flags & MREMAP_FIXED != 0 && self.new_addr & PAGE_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.flags & MREMAP_DONTUNMAP != 0 && self.flags & MREMAP_MAYMOVE == 0 {
            return Err(Error::InvalidArgument);
        }
        // Overflow check for old range.
        self.old_addr
            .checked_add(self.old_size)
            .ok_or(Error::InvalidArgument)?;
        Ok(())
    }

    /// Return `true` if the mapping may be moved to a new address.
    pub const fn may_move(&self) -> bool {
        self.flags & MREMAP_MAYMOVE != 0
    }

    /// Return `true` if the destination address is fixed.
    pub const fn is_fixed(&self) -> bool {
        self.flags & MREMAP_FIXED != 0
    }

    /// Return `true` if the old mapping should be retained after a move.
    pub const fn dont_unmap(&self) -> bool {
        self.flags & MREMAP_DONTUNMAP != 0
    }

    /// Return the page-aligned old size.
    pub fn aligned_old_size(&self) -> u64 {
        align_up(self.old_size)
    }

    /// Return the page-aligned new size.
    pub fn aligned_new_size(&self) -> u64 {
        align_up(self.new_size)
    }
}

// ---------------------------------------------------------------------------
// RemapAction — what must happen to satisfy the request
// ---------------------------------------------------------------------------

/// The action that `mremap` must take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemapAction {
    /// Grow the mapping in place.
    GrowInPlace { additional_pages: u64 },
    /// Shrink the mapping in place.
    ShrinkInPlace { freed_pages: u64 },
    /// Move the mapping to a new address (implies unmap from old).
    MoveMapping { new_addr: u64, copy_pages: u64 },
    /// Mapping size unchanged, no-op.
    NoChange,
}

// ---------------------------------------------------------------------------
// MremapResult — outcome
// ---------------------------------------------------------------------------

/// Result of a successful `mremap` call.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MremapResult {
    /// New base address of the mapping.
    pub new_addr: u64,
    /// Actual new size of the mapping (page-aligned).
    pub new_size: u64,
    /// The action taken.
    pub action: Option<RemapAction>,
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

/// Align `n` up to the next page boundary.
fn align_up(n: u64) -> u64 {
    n.wrapping_add(PAGE_SIZE - 1) & !PAGE_MASK
}

/// Determine the remap action from the validated args.
fn determine_action(args: &MremapArgs) -> RemapAction {
    let old_pages = align_up(args.old_size) / PAGE_SIZE;
    let new_pages = align_up(args.new_size) / PAGE_SIZE;

    if new_pages == old_pages {
        return RemapAction::NoChange;
    }

    if new_pages > old_pages {
        // Attempt to grow; may require a move.
        if args.may_move() {
            let new_addr = if args.is_fixed() {
                args.new_addr
            } else {
                // Stub: kernel would search for free space.
                0x0000_7FFF_0000_0000u64
            };
            RemapAction::MoveMapping {
                new_addr,
                copy_pages: old_pages,
            }
        } else {
            RemapAction::GrowInPlace {
                additional_pages: new_pages - old_pages,
            }
        }
    } else {
        RemapAction::ShrinkInPlace {
            freed_pages: old_pages - new_pages,
        }
    }
}

impl Default for RemapAction {
    fn default() -> Self {
        RemapAction::NoChange
    }
}

// ---------------------------------------------------------------------------
// Public syscall handler
// ---------------------------------------------------------------------------

/// `mremap` — resize or relocate a memory mapping.
///
/// The mapping starting at `old_addr` of `old_size` bytes is changed to
/// `new_size` bytes. If `MREMAP_MAYMOVE` is set, the kernel may choose
/// a new address. If `MREMAP_FIXED` is also set, the mapping is placed
/// at exactly `new_addr`.
///
/// Returns the new base address of the mapping on success.
///
/// # Errors
///
/// | `Error`           | Condition                                         |
/// |-------------------|---------------------------------------------------|
/// | `InvalidArgument` | Any field fails validation (see `MremapArgs`)     |
/// | `NotImplemented`  | In-place growth is not yet supported (stub)       |
///
/// Reference: Linux mremap(2).
pub fn do_mremap(args: &MremapArgs) -> Result<MremapResult> {
    args.validate()?;

    let action = determine_action(args);

    let (new_addr, new_size) = match action {
        RemapAction::NoChange => (args.old_addr, align_up(args.old_size)),
        RemapAction::ShrinkInPlace { .. } => (args.old_addr, align_up(args.new_size)),
        RemapAction::GrowInPlace { .. } => {
            // Stub: real implementation tries to extend the VMA in place.
            return Err(Error::NotImplemented);
        }
        RemapAction::MoveMapping { new_addr, .. } => (new_addr, align_up(args.new_size)),
    };

    Ok(MremapResult {
        new_addr,
        new_size,
        action: Some(action),
    })
}

/// Validate `mremap` arguments without performing the remap.
pub fn validate_mremap_args(args: &MremapArgs) -> Result<()> {
    args.validate()
}
