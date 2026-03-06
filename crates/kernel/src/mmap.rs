// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `mmap` implementation — memory mapping for user-space processes.
//!
//! Supports anonymous mappings (zero-filled pages) and the foundation
//! for file-backed mappings. Implements the POSIX `mmap(2)` semantics.
//!
//! Reference: POSIX.1-2024 §mmap, Linux `mm/mmap.c`.

use oncrix_lib::{Error, Result};
use oncrix_mm::addr::{PAGE_SIZE, VirtAddr};
use oncrix_mm::address_space::{AddressSpace, Protection, RegionKind, VmRegion};
use oncrix_mm::address_space::{USER_SPACE_END, USER_SPACE_START};

/// mmap protection flags (matches POSIX values).
pub mod prot {
    /// Pages may not be accessed.
    pub const PROT_NONE: u64 = 0x0;
    /// Pages may be read.
    pub const PROT_READ: u64 = 0x1;
    /// Pages may be written.
    pub const PROT_WRITE: u64 = 0x2;
    /// Pages may be executed.
    pub const PROT_EXEC: u64 = 0x4;
}

/// mmap flags (matches Linux values).
pub mod map_flags {
    /// Share changes (shared memory).
    pub const MAP_SHARED: u64 = 0x01;
    /// Changes are private (copy-on-write).
    pub const MAP_PRIVATE: u64 = 0x02;
    /// Place mapping at exactly the specified address.
    pub const MAP_FIXED: u64 = 0x10;
    /// Mapping is not backed by any file (zero-filled).
    pub const MAP_ANONYMOUS: u64 = 0x20;
}

/// Result of a successful mmap call.
#[derive(Debug)]
pub struct MmapResult {
    /// Start address of the mapping.
    pub addr: VirtAddr,
    /// Size of the mapping (page-aligned).
    pub size: u64,
}

/// Perform the mmap operation on an address space.
///
/// For anonymous mappings (`MAP_ANONYMOUS`), pages are zero-filled
/// on demand (lazy allocation). The actual page table entries are
/// created on page fault.
///
/// For file-backed mappings, the `fd` and `offset` parameters
/// specify which file data to map. (Not yet fully implemented.)
pub fn do_mmap(
    space: &mut AddressSpace,
    addr: u64,
    length: u64,
    prot_flags: u64,
    flags: u64,
    _fd: u64,
    _offset: u64,
) -> Result<MmapResult> {
    // Validate length.
    if length == 0 {
        return Err(Error::InvalidArgument);
    }

    // Page-align length upward.
    let aligned_len = page_align_up(length);

    // Validate flags — must be either SHARED or PRIVATE, not both.
    let is_private = flags & map_flags::MAP_PRIVATE != 0;
    let is_shared = flags & map_flags::MAP_SHARED != 0;
    if is_private == is_shared {
        return Err(Error::InvalidArgument);
    }

    let is_anonymous = flags & map_flags::MAP_ANONYMOUS != 0;
    let is_fixed = flags & map_flags::MAP_FIXED != 0;

    // For now, only support anonymous private mappings.
    if !is_anonymous {
        return Err(Error::NotImplemented);
    }

    // Convert prot flags to our Protection type.
    let protection = prot_to_protection(prot_flags);

    // Determine the mapping address.
    let map_addr = if is_fixed {
        // MAP_FIXED: use the exact address (must be page-aligned).
        let va = VirtAddr::new(addr);
        if !va.is_aligned() {
            return Err(Error::InvalidArgument);
        }
        validate_user_range(va, aligned_len)?;
        va
    } else if addr != 0 {
        // Hint address: try it, fall back to auto-allocation.
        let va = VirtAddr::new(addr).align_down();
        if validate_user_range(va, aligned_len).is_ok() && !region_overlaps(space, va, aligned_len)
        {
            va
        } else {
            find_free_region(space, aligned_len)?
        }
    } else {
        // No address hint: find a free region.
        find_free_region(space, aligned_len)?
    };

    // Create and add the region.
    let region = VmRegion {
        start: map_addr,
        size: aligned_len,
        prot: protection,
        kind: RegionKind::Mmap,
    };

    space.add_region(region)?;

    Ok(MmapResult {
        addr: map_addr,
        size: aligned_len,
    })
}

/// Unmap a memory region (munmap).
///
/// Removes the region from the address space. The caller is
/// responsible for unmapping the actual page table entries and
/// freeing physical frames.
pub fn do_munmap(space: &mut AddressSpace, addr: u64, length: u64) -> Result<()> {
    if length == 0 {
        return Err(Error::InvalidArgument);
    }

    let va = VirtAddr::new(addr);
    if !va.is_aligned() {
        return Err(Error::InvalidArgument);
    }

    // Find and remove the region starting at this address.
    // Full munmap should handle partial unmaps, but for now
    // we only support exact region removal.
    space.remove_region(va)?;
    Ok(())
}

/// Convert POSIX prot flags to our Protection type.
fn prot_to_protection(prot_flags: u64) -> Protection {
    let mut p = 0u8;
    if prot_flags & prot::PROT_READ != 0 {
        p |= Protection::READ.0;
    }
    if prot_flags & prot::PROT_WRITE != 0 {
        p |= Protection::WRITE.0;
    }
    if prot_flags & prot::PROT_EXEC != 0 {
        p |= Protection::EXEC.0;
    }
    Protection(p)
}

/// Align a size up to the next page boundary.
fn page_align_up(size: u64) -> u64 {
    let ps = PAGE_SIZE as u64;
    (size + ps - 1) & !(ps - 1)
}

/// Validate that a range falls within user space.
fn validate_user_range(start: VirtAddr, size: u64) -> Result<()> {
    let end = start
        .as_u64()
        .checked_add(size)
        .ok_or(Error::InvalidArgument)?;
    if start.as_u64() < USER_SPACE_START || end > USER_SPACE_END {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Check if a region overlaps any existing region.
fn region_overlaps(space: &AddressSpace, start: VirtAddr, size: u64) -> bool {
    let end = start.as_u64().saturating_add(size);
    space.regions().any(|r| {
        let r_end = r.start.as_u64().saturating_add(r.size);
        start.as_u64() < r_end && end > r.start.as_u64()
    })
}

/// Find a free region in the address space for a mapping of the given size.
///
/// Uses a simple top-down search starting from below the stack area.
/// This mirrors the Linux default mmap allocation strategy.
fn find_free_region(space: &AddressSpace, size: u64) -> Result<VirtAddr> {
    // Search from high addresses down (below stack, above heap).
    // mmap region: 0x0000_7000_0000_0000 downward.
    let mmap_top: u64 = 0x0000_7000_0000_0000;
    let mmap_bottom: u64 = USER_SPACE_START;

    let mut candidate = mmap_top.saturating_sub(size);
    // Align down to page.
    candidate &= !(PAGE_SIZE as u64 - 1);

    // Try decreasing addresses until we find a non-overlapping region.
    // Limit iterations to prevent infinite loop.
    for _ in 0..1024 {
        if candidate < mmap_bottom {
            return Err(Error::OutOfMemory);
        }

        let va = VirtAddr::new(candidate);
        if !region_overlaps(space, va, size) {
            return Ok(va);
        }

        // Move down by one page and try again.
        candidate = candidate.saturating_sub(PAGE_SIZE as u64);
        candidate &= !(PAGE_SIZE as u64 - 1);
    }

    Err(Error::OutOfMemory)
}
