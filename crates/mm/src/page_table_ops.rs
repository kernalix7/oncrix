// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! High-level page table manipulation operations.
//!
//! Provides batch and convenience operations on top of the low-level
//! page table entry structures. Supports mapping ranges, unmapping,
//! changing permissions for contiguous regions, and collecting dirty
//! page information.
//!
//! # Design
//!
//! ```text
//!  Caller
//!   │
//!   ├─ map_range(virt, phys, count, flags)
//!   │    └─ for each page → set PTE, TLB flush
//!   │
//!   ├─ unmap_range(virt, count)
//!   │    └─ for each page → clear PTE, TLB flush
//!   │
//!   └─ protect_range(virt, count, new_flags)
//!        └─ for each page → update PTE flags, TLB flush
//! ```
//!
//! # Key Types
//!
//! - [`MappingRequest`] — describes a mapping operation
//! - [`PageTableOps`] — batch operation executor
//! - [`MappingResult`] — outcome of a mapping operation
//!
//! Reference: Linux `arch/x86/mm/pgtable.c`, `mm/mmap.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size.
const PAGE_SIZE: u64 = 4096;

/// Maximum pages per batch operation.
const MAX_BATCH_PAGES: usize = 4096;

/// PTE flag: present.
const PTE_PRESENT: u64 = 1 << 0;

/// PTE flag: writable.
const PTE_WRITABLE: u64 = 1 << 1;

/// PTE flag: user-accessible.
const PTE_USER: u64 = 1 << 2;

/// PTE flag: no-execute.
const PTE_NO_EXEC: u64 = 1 << 63;

// -------------------------------------------------------------------
// MappingRequest
// -------------------------------------------------------------------

/// Describes a mapping operation.
#[derive(Debug, Clone, Copy)]
pub struct MappingRequest {
    /// Virtual start address (page-aligned).
    virt_start: u64,
    /// Physical start address (page-aligned).
    phys_start: u64,
    /// Number of pages to map.
    page_count: usize,
    /// PTE flags to apply.
    flags: u64,
}

impl MappingRequest {
    /// Create a new mapping request.
    pub const fn new(
        virt_start: u64,
        phys_start: u64,
        page_count: usize,
        flags: u64,
    ) -> Self {
        Self {
            virt_start,
            phys_start,
            page_count,
            flags,
        }
    }

    /// Return the virtual start address.
    pub const fn virt_start(&self) -> u64 {
        self.virt_start
    }

    /// Return the physical start address.
    pub const fn phys_start(&self) -> u64 {
        self.phys_start
    }

    /// Return the page count.
    pub const fn page_count(&self) -> usize {
        self.page_count
    }

    /// Return the flags.
    pub const fn flags(&self) -> u64 {
        self.flags
    }

    /// Validate the request.
    pub fn validate(&self) -> Result<()> {
        if self.virt_start % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.phys_start % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.page_count == 0 || self.page_count > MAX_BATCH_PAGES {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for MappingRequest {
    fn default() -> Self {
        Self::new(0, 0, 0, 0)
    }
}

// -------------------------------------------------------------------
// MappingResult
// -------------------------------------------------------------------

/// Outcome of a mapping batch operation.
#[derive(Debug, Clone, Copy)]
pub struct MappingResult {
    /// Number of pages successfully mapped.
    pub mapped: usize,
    /// Number of pages that failed.
    pub failed: usize,
    /// Whether TLB flush was performed.
    pub tlb_flushed: bool,
}

impl MappingResult {
    /// Create a successful result.
    pub const fn success(mapped: usize) -> Self {
        Self {
            mapped,
            failed: 0,
            tlb_flushed: true,
        }
    }

    /// Create a partial result.
    pub const fn partial(mapped: usize, failed: usize) -> Self {
        Self {
            mapped,
            failed,
            tlb_flushed: true,
        }
    }

    /// Check whether all pages were mapped.
    pub const fn is_complete(&self) -> bool {
        self.failed == 0
    }
}

// -------------------------------------------------------------------
// PteSlot
// -------------------------------------------------------------------

/// A simulated PTE slot for tracking mappings.
#[derive(Debug, Clone, Copy)]
struct PteSlot {
    /// Virtual address this slot maps.
    virt_addr: u64,
    /// Physical address mapped to.
    phys_addr: u64,
    /// Flags.
    flags: u64,
    /// Whether this slot is in use.
    valid: bool,
}

impl PteSlot {
    const fn empty() -> Self {
        Self {
            virt_addr: 0,
            phys_addr: 0,
            flags: 0,
            valid: false,
        }
    }
}

// -------------------------------------------------------------------
// PageTableOps
// -------------------------------------------------------------------

/// Maximum tracked PTE slots.
const MAX_SLOTS: usize = 512;

/// Batch page table operation executor.
pub struct PageTableOps {
    /// Simulated PTE storage.
    slots: [PteSlot; MAX_SLOTS],
    /// Number of valid slots.
    slot_count: usize,
    /// Total TLB flushes performed.
    tlb_flush_count: u64,
    /// Total mapping operations.
    map_ops: u64,
    /// Total unmap operations.
    unmap_ops: u64,
}

impl PageTableOps {
    /// Create a new operation executor.
    pub const fn new() -> Self {
        Self {
            slots: [const { PteSlot::empty() }; MAX_SLOTS],
            slot_count: 0,
            tlb_flush_count: 0,
            map_ops: 0,
            unmap_ops: 0,
        }
    }

    /// Return the number of active mappings.
    pub const fn active_mappings(&self) -> usize {
        self.slot_count
    }

    /// Return total TLB flushes.
    pub const fn tlb_flush_count(&self) -> u64 {
        self.tlb_flush_count
    }

    /// Return total map operations.
    pub const fn map_ops(&self) -> u64 {
        self.map_ops
    }

    /// Find the slot for a virtual address.
    fn find_slot(&self, virt_addr: u64) -> Option<usize> {
        for idx in 0..self.slot_count {
            if self.slots[idx].valid && self.slots[idx].virt_addr == virt_addr {
                return Some(idx);
            }
        }
        None
    }

    /// Map a range of pages.
    pub fn map_range(&mut self, request: &MappingRequest) -> Result<MappingResult> {
        request.validate()?;
        let mut mapped = 0usize;

        for i in 0..request.page_count() {
            let virt = request.virt_start() + (i as u64) * PAGE_SIZE;
            let phys = request.phys_start() + (i as u64) * PAGE_SIZE;

            if self.find_slot(virt).is_some() {
                // Already mapped — skip.
                continue;
            }
            if self.slot_count >= MAX_SLOTS {
                return Ok(MappingResult::partial(
                    mapped,
                    request.page_count() - mapped,
                ));
            }
            self.slots[self.slot_count] = PteSlot {
                virt_addr: virt,
                phys_addr: phys,
                flags: request.flags() | PTE_PRESENT,
                valid: true,
            };
            self.slot_count += 1;
            mapped += 1;
        }

        self.tlb_flush_count += 1;
        self.map_ops += 1;
        Ok(MappingResult::success(mapped))
    }

    /// Unmap a range of pages starting at `virt_start`.
    pub fn unmap_range(
        &mut self,
        virt_start: u64,
        page_count: usize,
    ) -> Result<usize> {
        if virt_start % PAGE_SIZE != 0 || page_count == 0 {
            return Err(Error::InvalidArgument);
        }

        let mut unmapped = 0usize;
        for i in 0..page_count {
            let virt = virt_start + (i as u64) * PAGE_SIZE;
            if let Some(slot_idx) = self.find_slot(virt) {
                self.slots[slot_idx].valid = false;
                unmapped += 1;
            }
        }

        if unmapped > 0 {
            self.tlb_flush_count += 1;
            self.unmap_ops += 1;
        }

        Ok(unmapped)
    }

    /// Change protection flags for a range.
    pub fn protect_range(
        &mut self,
        virt_start: u64,
        page_count: usize,
        new_flags: u64,
    ) -> Result<usize> {
        if virt_start % PAGE_SIZE != 0 || page_count == 0 {
            return Err(Error::InvalidArgument);
        }

        let mut updated = 0usize;
        for i in 0..page_count {
            let virt = virt_start + (i as u64) * PAGE_SIZE;
            if let Some(slot_idx) = self.find_slot(virt) {
                self.slots[slot_idx].flags =
                    (new_flags | PTE_PRESENT) & !0; // keep present
                updated += 1;
            }
        }

        if updated > 0 {
            self.tlb_flush_count += 1;
        }

        Ok(updated)
    }

    /// Look up the physical address for a virtual address.
    pub fn translate(&self, virt_addr: u64) -> Option<u64> {
        let page_virt = virt_addr & !(PAGE_SIZE - 1);
        let offset = virt_addr & (PAGE_SIZE - 1);
        self.find_slot(page_virt)
            .map(|idx| self.slots[idx].phys_addr + offset)
    }
}

impl Default for PageTableOps {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Create flags for a user read-write mapping.
pub const fn user_rw_flags() -> u64 {
    PTE_PRESENT | PTE_WRITABLE | PTE_USER
}

/// Create flags for a user read-only mapping.
pub const fn user_ro_flags() -> u64 {
    PTE_PRESENT | PTE_USER
}

/// Create flags for a kernel read-write mapping.
pub const fn kernel_rw_flags() -> u64 {
    PTE_PRESENT | PTE_WRITABLE | PTE_NO_EXEC
}

/// Map a single page and return the result.
pub fn map_single_page(
    ops: &mut PageTableOps,
    virt: u64,
    phys: u64,
    flags: u64,
) -> Result<()> {
    let req = MappingRequest::new(virt, phys, 1, flags);
    let result = ops.map_range(&req)?;
    if result.is_complete() {
        Ok(())
    } else {
        Err(Error::OutOfMemory)
    }
}
