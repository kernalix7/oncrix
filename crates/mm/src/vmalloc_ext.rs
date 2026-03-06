// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extended vmalloc subsystem for the ONCRIX kernel.
//!
//! Builds on the base vmalloc allocator to provide additional
//! capabilities:
//!
//! - **vmap / vunmap** — map arbitrary physical pages into a
//!   contiguous virtual region and unmap them with lazy TLB flush
//!   batching.
//! - **ioremap / iounmap** — map MMIO regions with proper cache
//!   attributes (uncacheable, write-combining, etc.).
//! - **Guard pages** — unmapped pages inserted between vmalloc
//!   areas to catch out-of-bounds accesses.
//! - **Lazy TLB flush** — batches TLB invalidations for vunmap
//!   operations to amortise the cost of IPI-based flushes.
//!
//! Key components:
//! - [`VmallocArea`] — descriptor for a single vmalloc region
//! - [`VmallocFlags`] — allocation/mapping flags
//! - [`CacheMode`] — cache attribute for MMIO mappings
//! - [`TlbFlushEntry`] — a pending TLB invalidation
//! - [`TlbFlushBatch`] — batched lazy TLB flush queue
//! - [`VmallocRegistry`] — area tracking and management
//! - [`VmallocExtStats`] — summary statistics
//!
//! Reference: Linux `mm/vmalloc.c`, `arch/x86/mm/ioremap.c`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Start of the vmalloc virtual address range (x86_64 canonical).
const VMALLOC_START: u64 = 0xFFFF_C900_0000_0000;

/// End of the vmalloc virtual address range (exclusive).
const VMALLOC_END: u64 = 0xFFFF_E900_0000_0000;

/// Guard page size (one page inserted after each area).
const GUARD_PAGE_SIZE: u64 = PAGE_SIZE;

/// Maximum number of vmalloc areas in the registry.
const MAX_AREAS: usize = 512;

/// Maximum number of physical pages per area.
const MAX_PAGES_PER_AREA: usize = 128;

/// Maximum number of pending TLB flush entries.
const MAX_TLB_FLUSH_ENTRIES: usize = 64;

/// Threshold: flush immediately when batch reaches this count.
const TLB_FLUSH_THRESHOLD: usize = 48;

/// Maximum age of a pending flush before forced drain (ns).
const TLB_FLUSH_MAX_AGE_NS: u64 = 10_000_000; // 10 ms

// ── VmallocFlags ──────────────────────────────────────────────────

/// Flags describing the type and properties of a vmalloc area.
pub struct VmallocFlags;

impl VmallocFlags {
    /// Area allocated via `vmalloc()`.
    pub const VM_ALLOC: u32 = 1 << 0;
    /// Area created by mapping existing pages (`vmap`).
    pub const VM_MAP: u32 = 1 << 1;
    /// Area created via `ioremap()`.
    pub const VM_IOREMAP: u32 = 1 << 2;
    /// DMA-coherent mapping.
    pub const VM_DMA_COHERENT: u32 = 1 << 3;
    /// Area is mappable into user space.
    pub const VM_USERMAP: u32 = 1 << 4;
    /// Area uses huge pages (2 MiB).
    pub const VM_HUGE_PAGES: u32 = 1 << 5;
    /// Area has been unmapped but TLB flush is pending.
    pub const VM_FLUSH_PENDING: u32 = 1 << 6;
    /// Area was created with write-combining cache mode.
    pub const VM_WRITE_COMBINE: u32 = 1 << 7;
}

// ── CacheMode ─────────────────────────────────────────────────────

/// Cache attribute for MMIO and special mappings.
///
/// Controls how the CPU caches accesses to the mapped region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CacheMode {
    /// Write-back (normal RAM, default).
    #[default]
    WriteBack,
    /// Uncacheable (MMIO, device registers).
    Uncacheable,
    /// Write-combining (frame buffers, GPU memory).
    WriteCombining,
    /// Write-through.
    WriteThrough,
    /// Write-protect.
    WriteProtect,
}

impl CacheMode {
    /// Returns the x86_64 PAT encoding index for this mode.
    ///
    /// In a real implementation these would map to PAT/MTRR
    /// entries; here we assign placeholder indices.
    pub fn pat_index(self) -> u8 {
        match self {
            Self::WriteBack => 0,
            Self::Uncacheable => 3,
            Self::WriteCombining => 1,
            Self::WriteThrough => 4,
            Self::WriteProtect => 5,
        }
    }
}

// ── VmallocArea ───────────────────────────────────────────────────

/// Descriptor for a single vmalloc / vmap / ioremap region.
///
/// Each area tracks its virtual base address, size, backing
/// physical pages, flags, and the address of the caller that
/// created it (for debugging / leak detection).
#[derive(Clone, Copy)]
pub struct VmallocArea {
    /// Virtual base address of this area.
    pub addr: u64,
    /// Total size in bytes (including guard page).
    pub size: u64,
    /// Allocation/mapping flags ([`VmallocFlags`]).
    pub flags: u32,
    /// Address of the caller that requested this area.
    pub caller: u64,
    /// Physical page addresses backing this area.
    pub pages: [u64; MAX_PAGES_PER_AREA],
    /// Number of valid entries in `pages`.
    pub nr_pages: usize,
    /// Cache mode for MMIO mappings.
    pub cache_mode: CacheMode,
    /// Unique area identifier.
    pub id: u32,
    /// Whether this area is currently in use.
    pub active: bool,
}

impl VmallocArea {
    /// Creates an empty, inactive area.
    const fn empty() -> Self {
        Self {
            addr: 0,
            size: 0,
            flags: 0,
            caller: 0,
            pages: [0u64; MAX_PAGES_PER_AREA],
            nr_pages: 0,
            cache_mode: CacheMode::WriteBack,
            id: 0,
            active: false,
        }
    }

    /// Returns the end address (exclusive) of this area.
    pub fn end_addr(&self) -> u64 {
        self.addr.saturating_add(self.size)
    }

    /// Returns the usable size (excluding guard page).
    pub fn usable_size(&self) -> u64 {
        self.size.saturating_sub(GUARD_PAGE_SIZE)
    }

    /// Returns `true` if `addr` falls within this area.
    pub fn contains(&self, addr: u64) -> bool {
        self.active && addr >= self.addr && addr < self.end_addr()
    }

    /// Returns `true` if this is an MMIO mapping.
    pub fn is_ioremap(&self) -> bool {
        self.flags & VmallocFlags::VM_IOREMAP != 0
    }

    /// Returns `true` if this is a vmap mapping.
    pub fn is_vmap(&self) -> bool {
        self.flags & VmallocFlags::VM_MAP != 0
    }

    /// Returns `true` if a TLB flush is pending.
    pub fn is_flush_pending(&self) -> bool {
        self.flags & VmallocFlags::VM_FLUSH_PENDING != 0
    }
}

// ── TlbFlushEntry ─────────────────────────────────────────────────

/// A pending TLB invalidation entry.
///
/// Records the virtual address range that must be flushed from
/// all CPU TLBs before the underlying physical pages can be
/// reused.
#[derive(Debug, Clone, Copy)]
pub struct TlbFlushEntry {
    /// Virtual start address to flush.
    pub addr: u64,
    /// Number of pages to flush.
    pub nr_pages: usize,
    /// Timestamp when this entry was queued (nanoseconds).
    pub queued_ns: u64,
    /// Whether this entry is active.
    pub active: bool,
}

impl TlbFlushEntry {
    /// Creates an empty, inactive entry.
    const fn empty() -> Self {
        Self {
            addr: 0,
            nr_pages: 0,
            queued_ns: 0,
            active: false,
        }
    }
}

// ── TlbFlushBatch ─────────────────────────────────────────────────

/// Batched lazy TLB flush queue.
///
/// Collects pending TLB invalidations and drains them either when
/// the batch reaches [`TLB_FLUSH_THRESHOLD`] entries or when the
/// oldest entry exceeds [`TLB_FLUSH_MAX_AGE_NS`].
pub struct TlbFlushBatch {
    /// Pending flush entries.
    entries: [TlbFlushEntry; MAX_TLB_FLUSH_ENTRIES],
    /// Number of active entries.
    count: usize,
    /// Total pages flushed (lifetime counter).
    total_flushed_pages: u64,
    /// Total flush operations (lifetime counter).
    total_flush_ops: u64,
}

impl Default for TlbFlushBatch {
    fn default() -> Self {
        Self::new()
    }
}

impl TlbFlushBatch {
    /// Creates a new, empty flush batch.
    pub const fn new() -> Self {
        Self {
            entries: [TlbFlushEntry::empty(); MAX_TLB_FLUSH_ENTRIES],
            count: 0,
            total_flushed_pages: 0,
            total_flush_ops: 0,
        }
    }

    /// Adds a range to the flush batch.
    ///
    /// If the batch is full, the caller should drain it first.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the batch is full.
    pub fn add(&mut self, addr: u64, nr_pages: usize, now_ns: u64) -> Result<()> {
        let slot = self
            .entries
            .iter_mut()
            .find(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = TlbFlushEntry {
            addr,
            nr_pages,
            queued_ns: now_ns,
            active: true,
        };
        self.count += 1;

        Ok(())
    }

    /// Returns `true` if the batch should be drained.
    ///
    /// Triggers on threshold count or oldest-entry age.
    pub fn should_drain(&self, now_ns: u64) -> bool {
        if self.count >= TLB_FLUSH_THRESHOLD {
            return true;
        }
        // Check age of oldest entry.
        for entry in &self.entries {
            if entry.active && now_ns.saturating_sub(entry.queued_ns) >= TLB_FLUSH_MAX_AGE_NS {
                return true;
            }
        }
        false
    }

    /// Drains all pending flush entries.
    ///
    /// In a real implementation, this would issue TLB shootdown
    /// IPIs to all CPUs. Here we just clear the batch.
    ///
    /// Returns the total number of pages that were flushed.
    pub fn drain(&mut self) -> usize {
        let mut total_pages = 0;

        for entry in &mut self.entries {
            if entry.active {
                total_pages += entry.nr_pages;
                entry.active = false;
            }
        }

        if total_pages > 0 {
            self.total_flushed_pages += total_pages as u64;
            self.total_flush_ops += 1;
        }
        self.count = 0;

        total_pages
    }

    /// Returns the number of pending flush entries.
    pub fn pending_count(&self) -> usize {
        self.count
    }

    /// Returns `true` if no flushes are pending.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Total pages flushed since creation.
    pub fn total_flushed_pages(&self) -> u64 {
        self.total_flushed_pages
    }

    /// Total flush operations since creation.
    pub fn total_flush_ops(&self) -> u64 {
        self.total_flush_ops
    }
}

// ── VmallocExtStats ───────────────────────────────────────────────

/// Summary statistics for the extended vmalloc subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmallocExtStats {
    /// Number of active vmalloc areas.
    pub total_areas: usize,
    /// Number of vmap areas.
    pub vmap_areas: usize,
    /// Number of ioremap areas.
    pub ioremap_areas: usize,
    /// Total pages across all active areas.
    pub total_pages: usize,
    /// Total bytes across all active areas.
    pub total_bytes: u64,
    /// Largest contiguous free region in vmalloc space.
    pub largest_free: u64,
    /// Pending TLB flush entries.
    pub pending_flushes: usize,
    /// Total TLB flush operations (lifetime).
    pub total_flush_ops: u64,
}

// ── VmallocRegistry ───────────────────────────────────────────────

/// Registry tracking all vmalloc / vmap / ioremap areas.
///
/// Manages allocation and deallocation of virtual address space
/// regions, guard page insertion, and lazy TLB flush batching.
pub struct VmallocRegistry {
    /// Area descriptors.
    areas: [VmallocArea; MAX_AREAS],
    /// Number of active areas.
    count: usize,
    /// Next unique area ID.
    next_id: u32,
    /// Next free virtual address (bump allocator).
    next_addr: u64,
    /// Total pages across all active areas.
    total_pages: usize,
    /// Lazy TLB flush batch.
    tlb_batch: TlbFlushBatch,
}

impl Default for VmallocRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl VmallocRegistry {
    /// Creates a new, empty registry.
    pub const fn new() -> Self {
        Self {
            areas: [VmallocArea::empty(); MAX_AREAS],
            count: 0,
            next_id: 1,
            next_addr: VMALLOC_START,
            total_pages: 0,
            tlb_batch: TlbFlushBatch::new(),
        }
    }

    // ── vmap / vunmap ────────────────────────────────────────────

    /// Maps an array of physical pages into contiguous virtual
    /// address space.
    ///
    /// The pages do not need to be physically contiguous. A guard
    /// page is appended after the mapping.
    ///
    /// # Arguments
    ///
    /// - `phys_pages` — array of physical page addresses.
    /// - `cache_mode` — cache attribute for the mapping.
    /// - `caller` — return address of the caller (for debugging).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — `phys_pages` is empty or
    ///   exceeds `MAX_PAGES_PER_AREA`.
    /// - [`Error::OutOfMemory`] — address space exhausted or area
    ///   table full.
    pub fn vmap(&mut self, phys_pages: &[u64], cache_mode: CacheMode, caller: u64) -> Result<u64> {
        if phys_pages.is_empty() || phys_pages.len() > MAX_PAGES_PER_AREA {
            return Err(Error::InvalidArgument);
        }

        let nr_pages = phys_pages.len();
        let data_size = nr_pages as u64 * PAGE_SIZE;
        let total_size = data_size + GUARD_PAGE_SIZE;

        let base = self.alloc_va(total_size)?;
        let idx = self.find_free_slot()?;

        let area = &mut self.areas[idx];
        area.addr = base;
        area.size = total_size;
        area.flags = VmallocFlags::VM_MAP;
        area.caller = caller;
        area.nr_pages = nr_pages;
        area.cache_mode = cache_mode;
        area.id = self.next_id;
        area.active = true;

        for (i, &phys) in phys_pages.iter().enumerate() {
            area.pages[i] = phys;
        }

        self.next_id = self.next_id.wrapping_add(1);
        self.count += 1;
        self.total_pages += nr_pages;

        Ok(base)
    }

    /// Unmaps a previously `vmap`'d region with lazy TLB flush.
    ///
    /// The area is marked inactive and a TLB flush entry is
    /// queued. The underlying pages are not freed (the caller
    /// owns them).
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — no active vmap area at `addr`.
    pub fn vunmap(&mut self, addr: u64, now_ns: u64) -> Result<()> {
        let area = self
            .areas
            .iter_mut()
            .find(|a| a.active && a.addr == addr && (a.flags & VmallocFlags::VM_MAP) != 0)
            .ok_or(Error::NotFound)?;

        let nr = area.nr_pages;
        area.active = false;
        area.flags |= VmallocFlags::VM_FLUSH_PENDING;

        self.count = self.count.saturating_sub(1);
        self.total_pages = self.total_pages.saturating_sub(nr);

        // Queue lazy TLB flush.
        let _ = self.tlb_batch.add(addr, nr, now_ns);

        Ok(())
    }

    // ── ioremap / iounmap ───────────────────────────────────────

    /// Maps a physical MMIO region into vmalloc address space.
    ///
    /// The mapping is uncacheable by default (suitable for device
    /// registers). Use `ioremap_wc` for write-combining regions.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — `size` is zero or exceeds
    ///   max.
    /// - [`Error::OutOfMemory`] — address space exhausted.
    pub fn ioremap(&mut self, phys: u64, size: u64) -> Result<u64> {
        self.ioremap_with_cache(phys, size, CacheMode::Uncacheable)
    }

    /// Maps a physical MMIO region with write-combining cache
    /// mode.
    ///
    /// Suitable for frame buffers and GPU memory.
    pub fn ioremap_wc(&mut self, phys: u64, size: u64) -> Result<u64> {
        self.ioremap_with_cache(phys, size, CacheMode::WriteCombining)
    }

    /// Maps a physical MMIO region with write-through cache
    /// mode.
    pub fn ioremap_wt(&mut self, phys: u64, size: u64) -> Result<u64> {
        self.ioremap_with_cache(phys, size, CacheMode::WriteThrough)
    }

    /// Core ioremap with explicit cache mode.
    fn ioremap_with_cache(&mut self, phys: u64, size: u64, cache_mode: CacheMode) -> Result<u64> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }

        let nr_pages = pages_for(size);
        if nr_pages > MAX_PAGES_PER_AREA {
            return Err(Error::InvalidArgument);
        }

        let total_size = nr_pages as u64 * PAGE_SIZE + GUARD_PAGE_SIZE;
        let base = self.alloc_va(total_size)?;
        let idx = self.find_free_slot()?;

        let mut flags = VmallocFlags::VM_IOREMAP;
        if cache_mode == CacheMode::WriteCombining {
            flags |= VmallocFlags::VM_WRITE_COMBINE;
        }

        let area = &mut self.areas[idx];
        area.addr = base;
        area.size = total_size;
        area.flags = flags;
        area.caller = 0;
        area.nr_pages = nr_pages;
        area.cache_mode = cache_mode;
        area.id = self.next_id;
        area.active = true;

        // Store contiguous physical addresses.
        for i in 0..nr_pages {
            area.pages[i] = phys + (i as u64) * PAGE_SIZE;
        }

        self.next_id = self.next_id.wrapping_add(1);
        self.count += 1;
        self.total_pages += nr_pages;

        Ok(base)
    }

    /// Unmaps a previously `ioremap`'d region.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — no active ioremap area at `addr`.
    pub fn iounmap(&mut self, addr: u64, now_ns: u64) -> Result<()> {
        let area = self
            .areas
            .iter_mut()
            .find(|a| a.active && a.addr == addr && a.is_ioremap())
            .ok_or(Error::NotFound)?;

        let nr = area.nr_pages;
        area.active = false;

        self.count = self.count.saturating_sub(1);
        self.total_pages = self.total_pages.saturating_sub(nr);

        // Queue lazy TLB flush.
        let _ = self.tlb_batch.add(addr, nr, now_ns);

        Ok(())
    }

    // ── Area lookup ──────────────────────────────────────────────

    /// Finds the area containing the given virtual address.
    pub fn find_area(&self, addr: u64) -> Option<&VmallocArea> {
        self.areas.iter().find(|a| a.contains(addr))
    }

    /// Finds the area by its base address.
    pub fn find_area_by_base(&self, base: u64) -> Option<&VmallocArea> {
        self.areas.iter().find(|a| a.active && a.addr == base)
    }

    /// Translates a vmalloc virtual address to its backing
    /// physical address.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — no area contains `addr`.
    /// - [`Error::InvalidArgument`] — `addr` falls in the guard
    ///   page.
    pub fn virt_to_phys(&self, addr: u64) -> Result<u64> {
        let area = self.find_area(addr).ok_or(Error::NotFound)?;

        let offset = addr - area.addr;
        let page_idx = (offset / PAGE_SIZE) as usize;

        if page_idx >= area.nr_pages {
            // Address is in the guard page.
            return Err(Error::InvalidArgument);
        }

        let page_offset = offset % PAGE_SIZE;
        Ok(area.pages[page_idx] + page_offset)
    }

    // ── TLB flush management ────────────────────────────────────

    /// Returns a reference to the TLB flush batch.
    pub fn tlb_batch(&self) -> &TlbFlushBatch {
        &self.tlb_batch
    }

    /// Drains the TLB flush batch if needed.
    ///
    /// Call this periodically (e.g. from a timer) or after a
    /// batch of vunmap/iounmap operations. Returns the number
    /// of pages flushed, or 0 if no drain was needed.
    pub fn maybe_drain_tlb(&mut self, now_ns: u64) -> usize {
        if self.tlb_batch.should_drain(now_ns) {
            self.tlb_batch.drain()
        } else {
            0
        }
    }

    /// Forces an immediate TLB flush of all pending entries.
    ///
    /// Returns the number of pages flushed.
    pub fn flush_tlb_now(&mut self) -> usize {
        self.tlb_batch.drain()
    }

    // ── Statistics ────────────────────────────────────────────────

    /// Returns summary statistics.
    pub fn stats(&self) -> VmallocExtStats {
        let vmap_areas = self
            .areas
            .iter()
            .filter(|a| a.active && a.is_vmap())
            .count();
        let ioremap_areas = self
            .areas
            .iter()
            .filter(|a| a.active && a.is_ioremap())
            .count();

        let total_bytes = self.total_pages as u64 * PAGE_SIZE;
        let largest_free = self.compute_largest_free();

        VmallocExtStats {
            total_areas: self.count,
            vmap_areas,
            ioremap_areas,
            total_pages: self.total_pages,
            total_bytes,
            largest_free,
            pending_flushes: self.tlb_batch.pending_count(),
            total_flush_ops: self.tlb_batch.total_flush_ops(),
        }
    }

    /// Number of active areas.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no areas are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Total pages across all active areas.
    pub fn total_pages(&self) -> usize {
        self.total_pages
    }

    // ── Internal helpers ────────────────────────────────────────

    /// Allocates virtual address space from the bump allocator.
    fn alloc_va(&mut self, size: u64) -> Result<u64> {
        let base = self.next_addr;
        let end = base.checked_add(size).ok_or(Error::OutOfMemory)?;

        if end > VMALLOC_END {
            return Err(Error::OutOfMemory);
        }

        self.next_addr = end;
        Ok(base)
    }

    /// Finds a free slot in the area array.
    fn find_free_slot(&self) -> Result<usize> {
        self.areas
            .iter()
            .position(|a| !a.active)
            .ok_or(Error::OutOfMemory)
    }

    /// Computes the largest contiguous free region.
    ///
    /// Sorts active areas by base address and finds the widest
    /// gap. O(n^2) sort is acceptable for n <= 512.
    fn compute_largest_free(&self) -> u64 {
        let mut bases = [0u64; MAX_AREAS];
        let mut ends = [0u64; MAX_AREAS];
        let mut n = 0usize;

        for a in &self.areas {
            if a.active {
                bases[n] = a.addr;
                ends[n] = a.end_addr();
                n += 1;
            }
        }

        if n == 0 {
            return VMALLOC_END - VMALLOC_START;
        }

        // Simple O(n^2) sort by base address.
        for i in 0..n {
            for j in (i + 1)..n {
                if bases[j] < bases[i] {
                    bases.swap(i, j);
                    ends.swap(i, j);
                }
            }
        }

        let mut largest: u64 = 0;

        // Gap before first area.
        let gap = bases[0].saturating_sub(VMALLOC_START);
        if gap > largest {
            largest = gap;
        }

        // Gaps between areas.
        for i in 1..n {
            let gap = bases[i].saturating_sub(ends[i - 1]);
            if gap > largest {
                largest = gap;
            }
        }

        // Gap after last area.
        let gap = VMALLOC_END.saturating_sub(ends[n - 1]);
        if gap > largest {
            largest = gap;
        }

        largest
    }
}

// ── Free functions ────────────────────────────────────────────────

/// Returns the number of pages needed to cover `size` bytes.
fn pages_for(size: u64) -> usize {
    size.div_ceil(PAGE_SIZE) as usize
}
