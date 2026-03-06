// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Early I/O remapping.
//!
//! Provides temporary virtual-to-physical mappings for memory-mapped I/O
//! regions during early boot, before the vmalloc subsystem and full page
//! table infrastructure are available. These mappings use a small, fixed
//! pool of pre-allocated virtual address slots.
//!
//! # Use cases
//!
//! - Reading ACPI tables from firmware-provided physical addresses
//! - Accessing the local APIC, I/O APIC, and HPET during early init
//! - Probing PCI configuration space before PCI subsystem init
//! - Accessing BIOS/EFI data regions
//!
//! # Design
//!
//! The early ioremap pool is a fixed array of [`EarlyIoSlot`] entries,
//! each capable of mapping a contiguous physical region into a
//! pre-assigned virtual address window. Slots are allocated from a
//! bitmap and freed back when the mapping is no longer needed.
//!
//! Once the full vmalloc/ioremap infrastructure is online, all early
//! mappings must be torn down and the pool deactivated via
//! [`EarlyIoremap::deactivate`].
//!
//! # Types
//!
//! - [`EarlyIoSlot`] — a single mapping slot
//! - [`EarlyIoMapping`] — handle returned to the caller
//! - [`EarlyIoremap`] — the main early ioremap manager
//! - [`EarlyIoremapStats`] — allocation statistics
//!
//! Reference: Linux `mm/early_ioremap.c`, `arch/x86/mm/ioremap.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Page mask for alignment.
const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

/// Number of early ioremap slots.
const NR_FIX_BTMAPS: usize = 16;

/// Maximum size of a single early mapping (1 MiB).
const MAX_MAP_SIZE: u64 = 1024 * 1024;

/// Maximum pages per slot (MAX_MAP_SIZE / PAGE_SIZE).
const MAX_PAGES_PER_SLOT: u64 = MAX_MAP_SIZE / PAGE_SIZE;

/// Virtual base address for the early ioremap region.
///
/// In a real kernel this comes from the fixmap area. Here we use a
/// sentinel in high virtual address space.
const EARLY_IOREMAP_BASE: u64 = 0xFFFF_FF00_0000_0000;

/// Size of each slot's virtual window.
const SLOT_SIZE: u64 = MAX_MAP_SIZE + PAGE_SIZE; // extra page for alignment

/// Slot state: free.
const SLOT_FREE: u8 = 0;

/// Slot state: in use.
const SLOT_IN_USE: u8 = 1;

/// Memory type: uncacheable (UC).
const MEM_TYPE_UC: u8 = 0;

/// Memory type: write-combining (WC).
const MEM_TYPE_WC: u8 = 1;

/// Memory type: write-back (WB).
const MEM_TYPE_WB: u8 = 2;

/// Memory type: write-through (WT).
const MEM_TYPE_WT: u8 = 3;

// -------------------------------------------------------------------
// EarlyIoSlot
// -------------------------------------------------------------------

/// A single early I/O mapping slot.
///
/// Each slot covers a virtual address window of [`SLOT_SIZE`] bytes and
/// can map a contiguous physical region within that window.
#[derive(Debug, Clone, Copy)]
pub struct EarlyIoSlot {
    /// Virtual base address of this slot's window.
    virt_base: u64,
    /// Physical address being mapped (0 if free).
    phys_addr: u64,
    /// Size of the mapping in bytes.
    size: u64,
    /// Memory type (UC, WC, WB, WT).
    mem_type: u8,
    /// Slot state (free or in use).
    state: u8,
    /// Slot index.
    index: u8,
    /// Number of pages mapped.
    nr_pages: u64,
}

impl EarlyIoSlot {
    /// Creates a new free slot at the given index.
    fn new(index: usize) -> Self {
        Self {
            virt_base: EARLY_IOREMAP_BASE + (index as u64) * SLOT_SIZE,
            phys_addr: 0,
            size: 0,
            mem_type: MEM_TYPE_UC,
            state: SLOT_FREE,
            index: index as u8,
            nr_pages: 0,
        }
    }

    /// Returns true if the slot is free.
    pub fn is_free(&self) -> bool {
        self.state == SLOT_FREE
    }

    /// Returns the virtual address of the mapped region.
    ///
    /// The returned address includes the page offset from the original
    /// physical address, so the caller gets a pointer into the exact
    /// byte requested.
    pub fn mapped_vaddr(&self) -> u64 {
        if self.state != SLOT_IN_USE {
            return 0;
        }
        let page_offset = self.phys_addr & !PAGE_MASK;
        self.virt_base + page_offset
    }

    /// Returns the physical address.
    pub fn phys_addr(&self) -> u64 {
        self.phys_addr
    }

    /// Returns the mapping size.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the memory type.
    pub fn mem_type(&self) -> u8 {
        self.mem_type
    }

    /// Returns the slot index.
    pub fn index(&self) -> u8 {
        self.index
    }

    /// Activates the slot with a mapping.
    fn activate(&mut self, phys_addr: u64, size: u64, mem_type: u8) {
        self.phys_addr = phys_addr;
        self.size = size;
        self.mem_type = mem_type;
        self.state = SLOT_IN_USE;
        self.nr_pages = pages_for_range(phys_addr, size);
    }

    /// Releases the slot.
    fn release(&mut self) {
        self.phys_addr = 0;
        self.size = 0;
        self.mem_type = MEM_TYPE_UC;
        self.state = SLOT_FREE;
        self.nr_pages = 0;
    }
}

impl Default for EarlyIoSlot {
    fn default() -> Self {
        Self::new(0)
    }
}

// -------------------------------------------------------------------
// EarlyIoMapping
// -------------------------------------------------------------------

/// Handle returned to the caller for an active early I/O mapping.
///
/// The caller must pass this handle to [`EarlyIoremap::unmap`] when
/// the mapping is no longer needed.
#[derive(Debug, Clone, Copy)]
pub struct EarlyIoMapping {
    /// Virtual address of the mapping (includes page offset).
    pub vaddr: u64,
    /// Physical address that was mapped.
    pub phys_addr: u64,
    /// Size of the mapping.
    pub size: u64,
    /// Slot index used.
    pub slot: u8,
}

impl EarlyIoMapping {
    /// Returns the virtual address.
    pub fn vaddr(&self) -> u64 {
        self.vaddr
    }

    /// Returns the end virtual address (exclusive).
    pub fn vaddr_end(&self) -> u64 {
        self.vaddr + self.size
    }
}

// -------------------------------------------------------------------
// EarlyIoremapStats
// -------------------------------------------------------------------

/// Statistics for the early ioremap subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct EarlyIoremapStats {
    /// Total mappings created.
    pub total_maps: u64,
    /// Total mappings released.
    pub total_unmaps: u64,
    /// Failed mapping attempts (no free slot).
    pub map_failures: u64,
    /// Peak simultaneous mappings.
    pub peak_in_use: u32,
    /// Currently active mappings.
    pub current_in_use: u32,
    /// Total pages mapped.
    pub total_pages_mapped: u64,
}

impl EarlyIoremapStats {
    /// Resets all statistics.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// Helper functions
// -------------------------------------------------------------------

/// Computes the number of pages needed to cover a physical range.
fn pages_for_range(phys_addr: u64, size: u64) -> u64 {
    if size == 0 {
        return 0;
    }
    let start_page = phys_addr & PAGE_MASK;
    let end = phys_addr + size;
    let end_page = (end + PAGE_SIZE - 1) & PAGE_MASK;
    (end_page - start_page) / PAGE_SIZE
}

/// Aligns a physical address down to a page boundary.
fn page_align_down(addr: u64) -> u64 {
    addr & PAGE_MASK
}

// -------------------------------------------------------------------
// EarlyIoremap
// -------------------------------------------------------------------

/// Early I/O remapping manager.
///
/// Manages a fixed pool of virtual address slots for mapping physical
/// I/O regions during early boot. Must be deactivated once the full
/// ioremap/vmalloc infrastructure is available.
pub struct EarlyIoremap {
    /// Mapping slots.
    slots: [EarlyIoSlot; NR_FIX_BTMAPS],
    /// Whether the subsystem is active (early boot only).
    active: bool,
    /// Statistics.
    stats: EarlyIoremapStats,
}

impl EarlyIoremap {
    /// Creates and initializes the early ioremap subsystem.
    pub fn new() -> Self {
        let mut slots = [EarlyIoSlot::default(); NR_FIX_BTMAPS];
        for (i, slot) in slots.iter_mut().enumerate() {
            *slot = EarlyIoSlot::new(i);
        }
        Self {
            slots,
            active: true,
            stats: EarlyIoremapStats::default(),
        }
    }

    /// Maps a physical I/O region into virtual address space.
    ///
    /// Returns an [`EarlyIoMapping`] handle that must be passed to
    /// [`unmap`](Self::unmap) when the mapping is no longer needed.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` — subsystem is inactive, size is zero, or
    ///   the mapping exceeds the maximum slot size.
    /// - `OutOfMemory` — no free slot available.
    pub fn map(&mut self, phys_addr: u64, size: u64, mem_type: u8) -> Result<EarlyIoMapping> {
        if !self.active {
            return Err(Error::InvalidArgument);
        }
        if size == 0 || size > MAX_MAP_SIZE {
            return Err(Error::InvalidArgument);
        }

        // Find a free slot.
        let slot_idx = self.slots.iter().position(|s| s.is_free()).ok_or_else(|| {
            self.stats.map_failures += 1;
            Error::OutOfMemory
        })?;

        self.slots[slot_idx].activate(phys_addr, size, mem_type);

        let vaddr = self.slots[slot_idx].mapped_vaddr();
        let nr_pages = self.slots[slot_idx].nr_pages;

        self.stats.total_maps += 1;
        self.stats.current_in_use += 1;
        self.stats.total_pages_mapped += nr_pages;
        if self.stats.current_in_use > self.stats.peak_in_use {
            self.stats.peak_in_use = self.stats.current_in_use;
        }

        Ok(EarlyIoMapping {
            vaddr,
            phys_addr,
            size,
            slot: slot_idx as u8,
        })
    }

    /// Maps a physical region with uncacheable (UC) memory type.
    pub fn map_uc(&mut self, phys_addr: u64, size: u64) -> Result<EarlyIoMapping> {
        self.map(phys_addr, size, MEM_TYPE_UC)
    }

    /// Maps a physical region with write-back (WB) memory type.
    pub fn map_wb(&mut self, phys_addr: u64, size: u64) -> Result<EarlyIoMapping> {
        self.map(phys_addr, size, MEM_TYPE_WB)
    }

    /// Maps a physical region with write-combining (WC) memory type.
    pub fn map_wc(&mut self, phys_addr: u64, size: u64) -> Result<EarlyIoMapping> {
        self.map(phys_addr, size, MEM_TYPE_WC)
    }

    /// Unmaps a previously created early I/O mapping.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` — the slot index in the mapping is invalid.
    /// - `NotFound` — the slot is not in use or does not match.
    pub fn unmap(&mut self, mapping: &EarlyIoMapping) -> Result<()> {
        let idx = mapping.slot as usize;
        if idx >= NR_FIX_BTMAPS {
            return Err(Error::InvalidArgument);
        }
        if self.slots[idx].is_free() {
            return Err(Error::NotFound);
        }
        if self.slots[idx].phys_addr != mapping.phys_addr {
            return Err(Error::NotFound);
        }

        self.slots[idx].release();
        self.stats.total_unmaps += 1;
        self.stats.current_in_use = self.stats.current_in_use.saturating_sub(1);

        Ok(())
    }

    /// Deactivates the early ioremap subsystem.
    ///
    /// Must be called once the full vmalloc/ioremap infrastructure is
    /// online. Any still-active mappings are forcibly released.
    pub fn deactivate(&mut self) -> u32 {
        let mut leaked = 0u32;
        for slot in &mut self.slots {
            if !slot.is_free() {
                slot.release();
                leaked += 1;
            }
        }
        self.active = false;
        self.stats.current_in_use = 0;
        leaked
    }

    /// Returns true if the subsystem is still active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Returns the number of free slots.
    pub fn free_slots(&self) -> usize {
        self.slots.iter().filter(|s| s.is_free()).count()
    }

    /// Returns the number of in-use slots.
    pub fn in_use_slots(&self) -> usize {
        NR_FIX_BTMAPS - self.free_slots()
    }

    /// Returns a reference to a slot by index.
    pub fn slot(&self, index: usize) -> Option<&EarlyIoSlot> {
        if index >= NR_FIX_BTMAPS {
            return None;
        }
        Some(&self.slots[index])
    }

    /// Finds the slot that maps the given virtual address.
    pub fn find_by_vaddr(&self, vaddr: u64) -> Option<&EarlyIoSlot> {
        self.slots
            .iter()
            .find(|s| !s.is_free() && vaddr >= s.virt_base && vaddr < s.virt_base + SLOT_SIZE)
    }

    /// Finds the slot that maps the given physical address.
    pub fn find_by_phys(&self, phys_addr: u64) -> Option<&EarlyIoSlot> {
        self.slots.iter().find(|s| {
            !s.is_free()
                && phys_addr >= page_align_down(s.phys_addr)
                && phys_addr < s.phys_addr + s.size
        })
    }

    /// Returns statistics.
    pub fn stats(&self) -> &EarlyIoremapStats {
        &self.stats
    }

    /// Returns the total number of slots.
    pub fn total_slots(&self) -> usize {
        NR_FIX_BTMAPS
    }
}

impl Default for EarlyIoremap {
    fn default() -> Self {
        Self::new()
    }
}
