// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Lazy vmalloc page table population.
//!
//! When the kernel maps a large vmalloc region at boot or module load
//! time, eagerly populating every page table entry is wasteful if only
//! a fraction of the region will actually be accessed. This module
//! implements *lazy population*: the page tables for a vmalloc area
//! are created on demand when a page fault occurs within the area.
//!
//! # Design
//!
//! 1. [`LazyVmallocArea::create_lazy`] reserves virtual address space
//!    and records the intended mapping parameters but does **not**
//!    install page table entries.
//! 2. When the CPU faults on an address inside the area,
//!    [`FaultHandler::handle_fault`] allocates a physical frame,
//!    installs the PTE, and returns.
//! 3. [`LazyVmallocArea::populate_range`] allows eager pre-population
//!    of a sub-range (e.g. when code knows it will touch every page).
//! 4. [`LazyVmallocArea::convert_to_eager`] populates all remaining
//!    un-faulted pages in one pass.
//!
//! # Concurrency
//!
//! In SMP environments, the fault handler must take a per-area lock
//! (stubbed here as a boolean flag) to prevent two CPUs from racing
//! on the same PTE.
//!
//! Reference: Linux `mm/vmalloc.c` (lazy TLB propagation),
//! `arch/x86/mm/fault.c` (vmalloc fault path).

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────────────────

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Start of the vmalloc virtual address range.
const VMALLOC_START: u64 = 0xFFFF_C900_0000_0000;

/// End of the vmalloc virtual address range (exclusive).
const VMALLOC_END: u64 = 0xFFFF_E900_0000_0000;

/// Maximum number of lazy vmalloc areas tracked.
const MAX_LAZY_AREAS: usize = 64;

/// Maximum number of pages per lazy area (256 KiB).
const MAX_PAGES_PER_AREA: usize = 64;

/// Guard page inserted after each area.
const GUARD_PAGE_SIZE: u64 = PAGE_SIZE;

/// Maximum number of pending faults queued.
const MAX_PENDING_FAULTS: usize = 32;

// ── LazyState ───────────────────────────────────────────────────────────────

/// Population state of a lazy vmalloc area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LazyState {
    /// Area reserved but no pages populated yet.
    Unpopulated,
    /// Some pages have been faulted in.
    PartiallyPopulated,
    /// All pages have been populated (eager).
    FullyPopulated,
    /// Area has been freed.
    Freed,
}

impl Default for LazyState {
    fn default() -> Self {
        Self::Unpopulated
    }
}

// ── VmallocPte ──────────────────────────────────────────────────────────────

/// Page table entry descriptor for a single page within a lazy area.
///
/// This is a software-level record; the actual hardware PTE is
/// installed by the fault handler.
#[derive(Debug, Clone, Copy)]
pub struct VmallocPte {
    /// Virtual address this PTE covers.
    pub virt_addr: u64,
    /// Physical frame number (0 = not populated).
    pub phys_frame: u64,
    /// PTE flags (PRESENT, WRITABLE, NO_EXEC, etc.).
    pub flags: u64,
    /// Whether this PTE has been installed in hardware.
    pub populated: bool,
    /// Whether the page was faulted in (vs. pre-populated).
    pub faulted: bool,
}

impl VmallocPte {
    /// Creates an empty (unpopulated) PTE descriptor.
    const fn empty() -> Self {
        Self {
            virt_addr: 0,
            phys_frame: 0,
            flags: 0,
            populated: false,
            faulted: false,
        }
    }
}

// ── PteFlags ────────────────────────────────────────────────────────────────

/// Common PTE flag constants for vmalloc mappings.
pub struct PteFlags;

impl PteFlags {
    /// Entry is present.
    pub const PRESENT: u64 = 1 << 0;
    /// Page is writable.
    pub const WRITABLE: u64 = 1 << 1;
    /// No-execute.
    pub const NO_EXEC: u64 = 1 << 63;
    /// Kernel default: present + writable + no-exec.
    pub const KERNEL_DEFAULT: u64 = Self::PRESENT | Self::WRITABLE | Self::NO_EXEC;
    /// Kernel code: present + no-write (read-only executable).
    pub const KERNEL_CODE: u64 = Self::PRESENT;
    /// Kernel read-only data: present + no-write + no-exec.
    pub const KERNEL_RODATA: u64 = Self::PRESENT | Self::NO_EXEC;
}

// ── LazyAreaConfig ──────────────────────────────────────────────────────────

/// Configuration for creating a lazy vmalloc area.
#[derive(Debug, Clone, Copy)]
pub struct LazyAreaConfig {
    /// Desired size in bytes (must be page-aligned).
    pub size: u64,
    /// PTE flags to apply to all pages.
    pub flags: u64,
    /// Whether to include a trailing guard page.
    pub guard_page: bool,
    /// Caller-chosen tag for debugging.
    pub tag: u32,
}

impl Default for LazyAreaConfig {
    fn default() -> Self {
        Self {
            size: PAGE_SIZE,
            flags: PteFlags::KERNEL_DEFAULT,
            guard_page: true,
            tag: 0,
        }
    }
}

// ── LazyVmallocArea ─────────────────────────────────────────────────────────

/// A lazily-populated vmalloc area.
///
/// Virtual address space is reserved immediately, but physical frames
/// and page table entries are installed only when accessed.
#[derive(Clone, Copy)]
pub struct LazyVmallocArea {
    /// Base virtual address.
    pub base: u64,
    /// Total size in bytes (excluding guard page).
    pub size: u64,
    /// Number of pages in this area.
    pub nr_pages: usize,
    /// Per-page PTE descriptors.
    ptes: [VmallocPte; MAX_PAGES_PER_AREA],
    /// Number of populated pages.
    populated_count: usize,
    /// Current population state.
    state: LazyState,
    /// PTE flags applied to new mappings.
    flags: u64,
    /// Whether a guard page follows this area.
    has_guard: bool,
    /// Caller tag for identification.
    tag: u32,
    /// Whether a fault is being handled (pseudo-lock).
    fault_in_progress: bool,
    /// Whether this area slot is in use.
    active: bool,
    /// Monotonically increasing area identifier.
    area_id: u32,
}

impl LazyVmallocArea {
    /// Creates an empty (inactive) area descriptor.
    const fn empty() -> Self {
        Self {
            base: 0,
            size: 0,
            nr_pages: 0,
            ptes: [const { VmallocPte::empty() }; MAX_PAGES_PER_AREA],
            populated_count: 0,
            state: LazyState::Freed,
            flags: 0,
            has_guard: false,
            tag: 0,
            fault_in_progress: false,
            active: false,
            area_id: 0,
        }
    }

    /// Returns the population state.
    pub const fn state(&self) -> LazyState {
        self.state
    }

    /// Returns `true` if all pages have been populated.
    pub const fn is_populated(&self) -> bool {
        matches!(self.state, LazyState::FullyPopulated)
    }

    /// Returns the number of populated pages.
    pub const fn populated_count(&self) -> usize {
        self.populated_count
    }

    /// Returns `true` if a fault is currently being handled.
    pub const fn is_fault_in_progress(&self) -> bool {
        self.fault_in_progress
    }

    /// Returns the area identifier.
    pub const fn area_id(&self) -> u32 {
        self.area_id
    }

    /// Returns `true` if `addr` falls within this area.
    pub const fn contains(&self, addr: u64) -> bool {
        self.active && addr >= self.base && addr < self.base + self.size
    }

    /// Returns the page index for a virtual address within this area.
    ///
    /// Returns `None` if the address is outside the area.
    pub const fn page_index_for(&self, addr: u64) -> Option<usize> {
        if !self.contains(addr) {
            return None;
        }
        Some(((addr - self.base) / PAGE_SIZE) as usize)
    }
}

// ── FaultInfo ───────────────────────────────────────────────────────────────

/// Information about a page fault within a lazy vmalloc area.
#[derive(Debug, Clone, Copy)]
pub struct FaultInfo {
    /// Faulting virtual address.
    pub fault_addr: u64,
    /// Area index that contains the address.
    pub area_index: usize,
    /// Page index within the area.
    pub page_index: usize,
    /// Whether the fault was a write access.
    pub is_write: bool,
    /// Whether the fault has been resolved.
    pub resolved: bool,
    /// Physical frame allocated to resolve the fault (0 if pending).
    pub allocated_frame: u64,
}

impl FaultInfo {
    /// Creates an empty fault info.
    const fn empty() -> Self {
        Self {
            fault_addr: 0,
            area_index: 0,
            page_index: 0,
            is_write: false,
            resolved: false,
            allocated_frame: 0,
        }
    }
}

// ── FaultHandler ────────────────────────────────────────────────────────────

/// Handles page faults for lazy vmalloc areas.
///
/// Maintains a record of recent faults for debugging and statistics.
pub struct FaultHandler {
    /// Recent fault records (circular buffer).
    faults: [FaultInfo; MAX_PENDING_FAULTS],
    /// Next write index.
    next_idx: usize,
    /// Total faults handled.
    pub total_faults: u64,
    /// Faults that required a new frame allocation.
    pub alloc_faults: u64,
    /// Faults on already-populated pages (spurious).
    pub spurious_faults: u64,
    /// Faults on addresses outside any lazy area.
    pub invalid_faults: u64,
}

impl FaultHandler {
    /// Creates a new fault handler.
    pub const fn new() -> Self {
        Self {
            faults: [const { FaultInfo::empty() }; MAX_PENDING_FAULTS],
            next_idx: 0,
            total_faults: 0,
            alloc_faults: 0,
            spurious_faults: 0,
            invalid_faults: 0,
        }
    }

    /// Handle a page fault at `fault_addr` within the set of lazy areas.
    ///
    /// `areas` — the lazy area table.
    /// `fault_addr` — the faulting virtual address.
    /// `is_write` — whether the access was a write.
    ///
    /// On success, returns the index of the area that was faulted in.
    pub fn handle_fault(
        &mut self,
        areas: &mut [LazyVmallocArea],
        fault_addr: u64,
        is_write: bool,
    ) -> Result<usize> {
        self.total_faults += 1;

        // Find the owning area.
        let area_idx = self.find_area(areas, fault_addr)?;
        let area = &mut areas[area_idx];

        // Compute page index.
        let page_idx = match area.page_index_for(fault_addr) {
            Some(idx) => idx,
            None => {
                self.invalid_faults += 1;
                return Err(Error::InvalidArgument);
            }
        };

        // Check if already populated (spurious fault / TLB stale).
        if area.ptes[page_idx].populated {
            self.spurious_faults += 1;
            // Record and return success — the TLB just needed a reload.
            self.record_fault(fault_addr, area_idx, page_idx, is_write, true, 0);
            return Ok(area_idx);
        }

        // Pseudo-lock: prevent concurrent fault handling on same area.
        if area.fault_in_progress {
            return Err(Error::Busy);
        }
        area.fault_in_progress = true;

        // Allocate a physical frame (stubbed).
        let frame = self.allocate_frame()?;

        // Install the PTE.
        let pte = &mut area.ptes[page_idx];
        pte.virt_addr = area.base + (page_idx as u64) * PAGE_SIZE;
        pte.phys_frame = frame;
        pte.flags = area.flags;
        pte.populated = true;
        pte.faulted = true;

        area.populated_count += 1;
        area.state = if area.populated_count >= area.nr_pages {
            LazyState::FullyPopulated
        } else {
            LazyState::PartiallyPopulated
        };

        area.fault_in_progress = false;
        self.alloc_faults += 1;
        self.record_fault(fault_addr, area_idx, page_idx, is_write, true, frame);

        Ok(area_idx)
    }

    /// Record a fault for debugging.
    fn record_fault(
        &mut self,
        addr: u64,
        area_idx: usize,
        page_idx: usize,
        is_write: bool,
        resolved: bool,
        frame: u64,
    ) {
        let info = &mut self.faults[self.next_idx];
        info.fault_addr = addr;
        info.area_index = area_idx;
        info.page_index = page_idx;
        info.is_write = is_write;
        info.resolved = resolved;
        info.allocated_frame = frame;
        self.next_idx = (self.next_idx + 1) % MAX_PENDING_FAULTS;
    }

    /// Find the area containing `addr`.
    fn find_area(&self, areas: &[LazyVmallocArea], addr: u64) -> Result<usize> {
        for (i, area) in areas.iter().enumerate() {
            if area.contains(addr) {
                return Ok(i);
            }
        }
        self.invalid_fault_count_only();
        Err(Error::NotFound)
    }

    /// Increment invalid fault counter (non-mutable helper).
    fn invalid_fault_count_only(&self) {
        // In a real implementation this would use an atomic counter.
        // Here we just acknowledge the fault was invalid; the mutable
        // counter is updated by the caller.
    }

    /// Stub: allocate a physical frame.
    fn allocate_frame(&self) -> Result<u64> {
        // Returns a synthetic frame number. Real implementation would
        // call the frame allocator.
        static NEXT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0x1000);
        Ok(NEXT.fetch_add(1, core::sync::atomic::Ordering::Relaxed))
    }
}

// ── LazyVmallocManager ──────────────────────────────────────────────────────

/// Manages all lazy vmalloc areas and their fault handler.
pub struct LazyVmallocManager {
    /// Lazy area table.
    areas: [LazyVmallocArea; MAX_LAZY_AREAS],
    /// Number of active areas.
    area_count: usize,
    /// Next virtual address to hand out.
    next_vaddr: u64,
    /// Monotonically increasing area ID generator.
    next_area_id: u32,
    /// Fault handler.
    pub fault_handler: FaultHandler,
    /// Total bytes reserved (including guard pages).
    total_reserved: u64,
}

impl LazyVmallocManager {
    /// Creates a new manager.
    pub const fn new() -> Self {
        Self {
            areas: [const { LazyVmallocArea::empty() }; MAX_LAZY_AREAS],
            area_count: 0,
            next_vaddr: VMALLOC_START,
            next_area_id: 1,
            fault_handler: FaultHandler::new(),
            total_reserved: 0,
        }
    }

    /// Reserve a new lazy vmalloc area.
    ///
    /// Virtual address space is allocated immediately but no physical
    /// frames or page table entries are created.
    pub fn create_lazy(&mut self, config: LazyAreaConfig) -> Result<u32> {
        if config.size == 0 || config.size % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        let nr_pages = (config.size / PAGE_SIZE) as usize;
        if nr_pages > MAX_PAGES_PER_AREA {
            return Err(Error::InvalidArgument);
        }
        if self.area_count >= MAX_LAZY_AREAS {
            return Err(Error::OutOfMemory);
        }

        let guard = if config.guard_page {
            GUARD_PAGE_SIZE
        } else {
            0
        };
        let total = config.size + guard;

        if self.next_vaddr + total > VMALLOC_END {
            return Err(Error::OutOfMemory);
        }

        // Find a free slot.
        let slot_idx = self.find_free_slot()?;
        let area = &mut self.areas[slot_idx];

        area.base = self.next_vaddr;
        area.size = config.size;
        area.nr_pages = nr_pages;
        area.flags = config.flags;
        area.has_guard = config.guard_page;
        area.tag = config.tag;
        area.state = LazyState::Unpopulated;
        area.populated_count = 0;
        area.fault_in_progress = false;
        area.active = true;
        area.area_id = self.next_area_id;

        // Initialise PTE descriptors with virtual addresses.
        for i in 0..nr_pages {
            area.ptes[i].virt_addr = area.base + (i as u64) * PAGE_SIZE;
            area.ptes[i].populated = false;
            area.ptes[i].faulted = false;
        }

        self.next_vaddr += total;
        self.next_area_id += 1;
        self.area_count += 1;
        self.total_reserved += total;

        Ok(area.area_id)
    }

    /// Eagerly populate a sub-range of a lazy area.
    ///
    /// `area_id` — the area to populate.
    /// `offset` — byte offset from the area base (page-aligned).
    /// `size` — number of bytes to populate (page-aligned).
    pub fn populate_range(&mut self, area_id: u32, offset: u64, size: u64) -> Result<usize> {
        if offset % PAGE_SIZE != 0 || size % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }

        let idx = self.find_area_by_id(area_id)?;
        let area = &mut self.areas[idx];

        let start_page = (offset / PAGE_SIZE) as usize;
        let page_count = (size / PAGE_SIZE) as usize;
        let end_page = start_page + page_count;
        if end_page > area.nr_pages {
            return Err(Error::InvalidArgument);
        }

        let mut populated = 0usize;
        for i in start_page..end_page {
            if !area.ptes[i].populated {
                let frame = self.fault_handler.allocate_frame()?;
                area.ptes[i].phys_frame = frame;
                area.ptes[i].flags = area.flags;
                area.ptes[i].populated = true;
                area.ptes[i].faulted = false; // pre-populated, not faulted
                area.populated_count += 1;
                populated += 1;
            }
        }

        area.state = if area.populated_count >= area.nr_pages {
            LazyState::FullyPopulated
        } else if area.populated_count > 0 {
            LazyState::PartiallyPopulated
        } else {
            LazyState::Unpopulated
        };

        Ok(populated)
    }

    /// Check whether a specific page in an area is populated.
    pub fn is_populated(&self, area_id: u32, page_index: usize) -> Result<bool> {
        let idx = self.find_area_by_id(area_id)?;
        let area = &self.areas[idx];
        if page_index >= area.nr_pages {
            return Err(Error::InvalidArgument);
        }
        Ok(area.ptes[page_index].populated)
    }

    /// Convert a lazy area to fully eager by populating all pages.
    pub fn convert_to_eager(&mut self, area_id: u32) -> Result<usize> {
        let idx = self.find_area_by_id(area_id)?;
        let size = self.areas[idx].size;
        self.populate_range(area_id, 0, size)
    }

    /// Free a lazy area and release all its physical frames.
    pub fn free_area(&mut self, area_id: u32) -> Result<()> {
        let idx = self.find_area_by_id(area_id)?;
        let area = &mut self.areas[idx];
        let total = area.size + if area.has_guard { GUARD_PAGE_SIZE } else { 0 };

        // Stub: release physical frames back to allocator.
        for pte in &mut area.ptes {
            if pte.populated {
                pte.populated = false;
                pte.phys_frame = 0;
            }
        }

        area.state = LazyState::Freed;
        area.active = false;
        area.populated_count = 0;
        self.area_count -= 1;
        self.total_reserved = self.total_reserved.saturating_sub(total);

        Ok(())
    }

    /// Handle a page fault, delegating to the internal fault handler.
    pub fn handle_fault(&mut self, fault_addr: u64, is_write: bool) -> Result<usize> {
        self.fault_handler
            .handle_fault(&mut self.areas, fault_addr, is_write)
    }

    /// Returns the number of active areas.
    pub const fn area_count(&self) -> usize {
        self.area_count
    }

    /// Returns the total reserved virtual address space in bytes.
    pub const fn total_reserved(&self) -> u64 {
        self.total_reserved
    }

    // ── Private helpers ─────────────────────────────────────────────

    /// Find a free area slot.
    fn find_free_slot(&self) -> Result<usize> {
        for (i, area) in self.areas.iter().enumerate() {
            if !area.active {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find an area by its ID.
    fn find_area_by_id(&self, area_id: u32) -> Result<usize> {
        for (i, area) in self.areas.iter().enumerate() {
            if area.active && area.area_id == area_id {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }
}
