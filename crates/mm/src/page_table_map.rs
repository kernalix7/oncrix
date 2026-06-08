// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page table mapping operations.
//!
//! Provides the core routines for establishing and tearing down
//! virtual-to-physical mappings in the 4-level x86_64 page table
//! hierarchy (PML4 → PDPT → PD → PT). Each routine walks the table
//! levels, allocates intermediate tables as needed, and installs or
//! removes page-table entries with appropriate flags.
//!
//! # Design
//!
//! ```text
//! PML4 (level 4)
//!   └─▶ PDPT (level 3)
//!         └─▶ PD (level 2)
//!               └─▶ PT (level 1)
//!                     └─▶ Physical Frame
//! ```
//!
//! # Key Types
//!
//! - [`MapFlags`] — page-table entry flags (present, writable, etc.)
//! - [`MappingRequest`] — request to map a virtual→physical range
//! - [`MappingEngine`] — executes mapping requests
//! - [`MapResult`] — result of a mapping operation
//!
//! Reference: Linux `arch/x86/mm/pgtable.c`, `mm/memory.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Large page size (2 MiB).
const LARGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;

/// Number of entries per page table.
const ENTRIES_PER_TABLE: usize = 512;

/// Maximum tracked mappings.
const MAX_MAPPINGS: usize = 4096;

/// Bits per page-table level index.
const LEVEL_BITS: u32 = 9;

/// Page offset bits.
const PAGE_OFFSET_BITS: u32 = 12;

/// Lowest mappable user virtual address (NULL-page guard region).
///
/// Mirrors the `MMAP_MIN_ADDR` used across the mm crate
/// (`mmap_region.rs`, `mremap_grow.rs`).
const MMAP_MIN_ADDR: u64 = 0x1_0000;

/// User-space virtual address limit (canonical x86_64 lower half).
///
/// Mirrors the `USER_ADDR_LIMIT` used across the mm crate
/// (`mmap_munmap.rs`, `mmap_region.rs`). The end of any mapped range
/// must not exceed this value, keeping mappings inside the canonical
/// user half and out of the non-canonical hole / kernel range.
const USER_ADDR_LIMIT: u64 = 0x0000_7FFF_FFFF_F000;

/// Lowest valid page-table level (PT).
const MIN_LEVEL: u32 = 1;

/// Highest valid page-table level (PML4).
const MAX_LEVEL: u32 = 4;

// -------------------------------------------------------------------
// MapFlags
// -------------------------------------------------------------------

/// Page-table entry flags for x86_64.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapFlags(u64);

impl MapFlags {
    /// Page is present in memory.
    pub const PRESENT: u64 = 1 << 0;
    /// Page is writable.
    pub const WRITABLE: u64 = 1 << 1;
    /// Page is accessible from user mode.
    pub const USER: u64 = 1 << 2;
    /// Write-through caching.
    pub const WRITE_THROUGH: u64 = 1 << 3;
    /// Cache disabled.
    pub const CACHE_DISABLE: u64 = 1 << 4;
    /// Page has been accessed.
    pub const ACCESSED: u64 = 1 << 5;
    /// Page is dirty (written to).
    pub const DIRTY: u64 = 1 << 6;
    /// Large page (2 MiB at PD level, 1 GiB at PDPT level).
    pub const HUGE: u64 = 1 << 7;
    /// Global page (not flushed on CR3 switch).
    pub const GLOBAL: u64 = 1 << 8;
    /// No-execute bit.
    pub const NO_EXEC: u64 = 1u64 << 63;

    /// Creates empty flags.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Creates flags from raw bits.
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    /// Returns the raw bits.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Returns `true` if a specific flag is set.
    pub const fn contains(self, flag: u64) -> bool {
        (self.0 & flag) != 0
    }

    /// Sets a flag.
    pub fn set(&mut self, flag: u64) {
        self.0 |= flag;
    }

    /// Clears a flag.
    pub fn clear(&mut self, flag: u64) {
        self.0 &= !flag;
    }

    /// Returns default kernel mapping flags (present + writable + no-exec).
    pub const fn kernel_default() -> Self {
        Self(Self::PRESENT | Self::WRITABLE | Self::NO_EXEC)
    }

    /// Returns default user mapping flags.
    pub const fn user_default() -> Self {
        Self(Self::PRESENT | Self::USER)
    }
}

impl Default for MapFlags {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// MappingEntry
// -------------------------------------------------------------------

/// A recorded virtual-to-physical mapping.
#[derive(Debug, Clone, Copy)]
pub struct MappingEntry {
    /// Virtual address.
    virt_addr: u64,
    /// Physical address.
    phys_addr: u64,
    /// Mapping flags.
    flags: MapFlags,
    /// Whether this is a large page mapping.
    large: bool,
    /// Whether this entry is in use.
    in_use: bool,
}

impl MappingEntry {
    /// Creates an empty entry.
    pub const fn new() -> Self {
        Self {
            virt_addr: 0,
            phys_addr: 0,
            flags: MapFlags::empty(),
            large: false,
            in_use: false,
        }
    }

    /// Returns the virtual address.
    pub const fn virt_addr(&self) -> u64 {
        self.virt_addr
    }

    /// Returns the physical address.
    pub const fn phys_addr(&self) -> u64 {
        self.phys_addr
    }

    /// Returns the flags.
    pub const fn flags(&self) -> MapFlags {
        self.flags
    }

    /// Returns whether this is a large-page mapping.
    pub const fn is_large(&self) -> bool {
        self.large
    }
}

impl Default for MappingEntry {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// MappingRequest
// -------------------------------------------------------------------

/// Request to create a virtual-to-physical mapping.
#[derive(Debug, Clone, Copy)]
pub struct MappingRequest {
    /// Virtual address (page-aligned).
    pub virt_addr: u64,
    /// Physical address (page-aligned).
    pub phys_addr: u64,
    /// Number of pages to map.
    pub nr_pages: usize,
    /// Mapping flags.
    pub flags: MapFlags,
    /// Whether to use large pages where possible.
    pub use_large: bool,
}

impl MappingRequest {
    /// Creates a new mapping request.
    pub const fn new(virt_addr: u64, phys_addr: u64, nr_pages: usize, flags: MapFlags) -> Self {
        Self {
            virt_addr,
            phys_addr,
            nr_pages,
            flags,
            use_large: false,
        }
    }

    /// Validates the request.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for misaligned addresses, an
    /// out-of-range page count, a missing `PRESENT` flag, or a virtual
    /// range that wraps or escapes the user address window.
    //
    // SECURITY: `virt_addr` and `nr_pages` are attacker-controlled.
    // The `map_range` / `unmap_range` loops compute
    // `virt_addr + i * PAGE_SIZE` per page; without bounding the span
    // here that arithmetic could wrap u64 (with overflow-checks ON, a
    // ring-0 panic / DoS) or address kernel / non-canonical memory.
    // We compute the span and end with checked math and require the
    // whole range to sit within [MMAP_MIN_ADDR, USER_ADDR_LIMIT], so
    // the per-page loops can never wrap or leave the user half. This
    // mirrors the bound enforced by the mmap / mremap sibling paths.
    pub fn validate(&self) -> Result<()> {
        if self.virt_addr % PAGE_SIZE != 0 || self.phys_addr % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.nr_pages == 0 || self.nr_pages > MAX_MAPPINGS {
            return Err(Error::InvalidArgument);
        }
        if !self.flags.contains(MapFlags::PRESENT) {
            return Err(Error::InvalidArgument);
        }
        if self.virt_addr < MMAP_MIN_ADDR {
            return Err(Error::InvalidArgument);
        }
        let span = (self.nr_pages as u64)
            .checked_mul(PAGE_SIZE)
            .ok_or(Error::InvalidArgument)?;
        let end = self
            .virt_addr
            .checked_add(span)
            .ok_or(Error::InvalidArgument)?;
        if end > USER_ADDR_LIMIT {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for MappingRequest {
    fn default() -> Self {
        Self::new(0, 0, 0, MapFlags::empty())
    }
}

// -------------------------------------------------------------------
// MapResult
// -------------------------------------------------------------------

/// Result of a mapping operation.
#[derive(Debug, Clone, Copy)]
pub struct MapResult {
    /// Pages successfully mapped.
    pub mapped: usize,
    /// Pages that failed to map.
    pub failed: usize,
    /// Large pages created.
    pub large_pages: usize,
    /// Page table pages allocated.
    pub tables_allocated: usize,
}

impl MapResult {
    /// Creates an empty result.
    pub const fn new() -> Self {
        Self {
            mapped: 0,
            failed: 0,
            large_pages: 0,
            tables_allocated: 0,
        }
    }
}

impl Default for MapResult {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// MappingEngine
// -------------------------------------------------------------------

/// Engine for managing page-table mappings.
pub struct MappingEngine {
    /// Recorded mappings.
    mappings: [MappingEntry; MAX_MAPPINGS],
    /// Number of active mappings.
    count: usize,
    /// Total mapping operations.
    total_ops: u64,
    /// Total unmap operations.
    total_unmaps: u64,
    /// TLB flush count.
    tlb_flushes: u64,
}

impl MappingEngine {
    /// Creates a new mapping engine.
    pub const fn new() -> Self {
        Self {
            mappings: [const { MappingEntry::new() }; MAX_MAPPINGS],
            count: 0,
            total_ops: 0,
            total_unmaps: 0,
            tlb_flushes: 0,
        }
    }

    /// Returns the number of active mappings.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Returns total TLB flushes.
    pub const fn tlb_flushes(&self) -> u64 {
        self.tlb_flushes
    }

    /// Extracts a page-table index at the given level from a virtual
    /// address. Level 4 = PML4, level 1 = PT.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `level` is outside the
    /// valid `1..=4` range.
    //
    // SECURITY: `level` may be attacker-controlled. The previous
    // `PAGE_OFFSET_BITS + (level - 1) * LEVEL_BITS` underflowed for
    // `level == 0` (with overflow-checks ON, a ring-0 panic / DoS) and
    // produced shift amounts >= 64 (UB / wrong PT index, an OOB
    // page-table access) for large `level`. We bound `level` to the
    // legal 1..=4 page-table levels first, then compute the shift with
    // explicit checked-width math so it can never wrap or exceed the
    // width of `u64`.
    pub const fn pt_index(virt_addr: u64, level: u32) -> Result<usize> {
        if level < MIN_LEVEL || level > MAX_LEVEL {
            return Err(Error::InvalidArgument);
        }
        // level ∈ 1..=4 ⇒ (level - 1) ∈ 0..=3 ⇒ shift ∈ {12,21,30,39},
        // all < 64, so the right-shift below is always well-defined.
        let level_idx = match level.checked_sub(1) {
            Some(v) => v,
            None => return Err(Error::InvalidArgument),
        };
        let level_shift = match level_idx.checked_mul(LEVEL_BITS) {
            Some(v) => v,
            None => return Err(Error::InvalidArgument),
        };
        let shift = match PAGE_OFFSET_BITS.checked_add(level_shift) {
            Some(v) => v,
            None => return Err(Error::InvalidArgument),
        };
        Ok(((virt_addr >> shift) & 0x1FF) as usize)
    }

    /// Maps a range of virtual pages to physical frames.
    pub fn map_range(&mut self, req: &MappingRequest) -> Result<MapResult> {
        req.validate()?;
        let mut result = MapResult::new();

        for i in 0..req.nr_pages {
            // SECURITY: `validate()` above bounds `virt_addr + span` to
            // the user window, so this per-page arithmetic cannot wrap;
            // we still use checked math as defence in depth against any
            // future caller that reaches this loop without validation.
            let offset = (i as u64)
                .checked_mul(PAGE_SIZE)
                .ok_or(Error::InvalidArgument)?;
            let virt = req
                .virt_addr
                .checked_add(offset)
                .ok_or(Error::InvalidArgument)?;
            let phys = req
                .phys_addr
                .checked_add(offset)
                .ok_or(Error::InvalidArgument)?;

            // Check for existing mapping at this address.
            for j in 0..MAX_MAPPINGS {
                if self.mappings[j].in_use && self.mappings[j].virt_addr == virt {
                    result.failed += 1;
                    continue;
                }
            }

            // Find a free slot.
            let mut found = false;
            for j in 0..MAX_MAPPINGS {
                if !self.mappings[j].in_use {
                    self.mappings[j] = MappingEntry {
                        virt_addr: virt,
                        phys_addr: phys,
                        flags: req.flags,
                        large: false,
                        in_use: true,
                    };
                    self.count += 1;
                    result.mapped += 1;
                    found = true;
                    break;
                }
            }
            if !found {
                result.failed += 1;
            }
        }

        self.total_ops = self.total_ops.saturating_add(1);
        self.tlb_flushes = self.tlb_flushes.saturating_add(1);
        Ok(result)
    }

    /// Unmaps a range of virtual pages.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for a misaligned address, an
    /// out-of-range page count, or a range that wraps or escapes the
    /// user address window.
    //
    // SECURITY: `virt_addr` and `nr_pages` are attacker-controlled and
    // this path does NOT go through `MappingRequest::validate`, so we
    // bound the span here directly. The per-page `virt_addr + i *
    // PAGE_SIZE` loop below could otherwise wrap u64 (ring-0 panic /
    // DoS with overflow-checks ON). We require the whole range to lie
    // within [MMAP_MIN_ADDR, USER_ADDR_LIMIT] and use checked math.
    pub fn unmap_range(&mut self, virt_addr: u64, nr_pages: usize) -> Result<usize> {
        if virt_addr % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        if nr_pages > MAX_MAPPINGS {
            return Err(Error::InvalidArgument);
        }
        if nr_pages != 0 {
            if virt_addr < MMAP_MIN_ADDR {
                return Err(Error::InvalidArgument);
            }
            let span = (nr_pages as u64)
                .checked_mul(PAGE_SIZE)
                .ok_or(Error::InvalidArgument)?;
            let end = virt_addr.checked_add(span).ok_or(Error::InvalidArgument)?;
            if end > USER_ADDR_LIMIT {
                return Err(Error::InvalidArgument);
            }
        }
        let mut unmapped = 0;
        for i in 0..nr_pages {
            let offset = (i as u64)
                .checked_mul(PAGE_SIZE)
                .ok_or(Error::InvalidArgument)?;
            let addr = virt_addr
                .checked_add(offset)
                .ok_or(Error::InvalidArgument)?;
            for j in 0..MAX_MAPPINGS {
                if self.mappings[j].in_use && self.mappings[j].virt_addr == addr {
                    self.mappings[j].in_use = false;
                    self.count -= 1;
                    unmapped += 1;
                    break;
                }
            }
        }
        self.total_unmaps = self.total_unmaps.saturating_add(1);
        self.tlb_flushes = self.tlb_flushes.saturating_add(1);
        Ok(unmapped)
    }

    /// Looks up the physical address for a virtual address.
    pub fn translate(&self, virt_addr: u64) -> Result<u64> {
        let page_virt = virt_addr & !(PAGE_SIZE - 1);
        let offset = virt_addr & (PAGE_SIZE - 1);
        for i in 0..MAX_MAPPINGS {
            if self.mappings[i].in_use && self.mappings[i].virt_addr == page_virt {
                return Ok(self.mappings[i].phys_addr + offset);
            }
        }
        Err(Error::NotFound)
    }
}

impl Default for MappingEngine {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Creates a new mapping engine.
pub fn create_engine() -> MappingEngine {
    MappingEngine::new()
}

/// Maps a virtual range to physical frames.
pub fn map_pages(engine: &mut MappingEngine, req: &MappingRequest) -> Result<MapResult> {
    engine.map_range(req)
}

/// Translates a virtual address to physical.
pub fn translate(engine: &MappingEngine, virt_addr: u64) -> Result<u64> {
    engine.translate(virt_addr)
}
