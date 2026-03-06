// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! vmalloc remap operations.
//!
//! Provides facilities for remapping vmalloc areas into user
//! virtual address spaces, mapping arbitrary physical pages into
//! kernel VA (vmap/vunmap), and mapping MMIO regions (ioremap).
//!
//! # Key Types
//!
//! - [`VmAreaFlags`] — area type flags (VM_IOREMAP, VM_ALLOC, etc.)
//! - [`VmallocRemapArea`] — descriptor for a remap area
//! - [`VmapBlockCache`] — per-CPU vmap block cache
//! - [`VmallocRemapper`] — central remap manager
//! - [`VmallocRemapStats`] — operation statistics
//!
//! Reference: Linux `mm/vmalloc.c`, `include/linux/vmalloc.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Start of the vmalloc virtual address range (x86_64).
const VMALLOC_START: u64 = 0xFFFF_C900_0000_0000;

/// End of the vmalloc virtual address range (x86_64).
const VMALLOC_END: u64 = 0xFFFF_E8FF_FFFF_FFFF;

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of remap areas.
const MAX_REMAP_AREAS: usize = 256;

/// Maximum pages per remap area.
const MAX_PAGES_PER_AREA: usize = 256;

/// Number of (logical) CPUs for per-CPU vmap block cache.
const NR_CPUS: usize = 8;

/// Number of vmap blocks per CPU cache.
const VMAP_BLOCKS_PER_CPU: usize = 16;

/// Guard page size between areas.
const GUARD_SIZE: u64 = PAGE_SIZE;

/// Maximum number of pending lazy TLB flush entries.
const MAX_LAZY_FLUSH: usize = 64;

// -------------------------------------------------------------------
// VmAreaFlags
// -------------------------------------------------------------------

/// Flags describing the type of a vmalloc remap area.
pub struct VmAreaFlags;

impl VmAreaFlags {
    /// Area mapped via `ioremap()` — MMIO.
    pub const VM_IOREMAP: u32 = 1 << 0;
    /// Area allocated via `vmalloc()`.
    pub const VM_ALLOC: u32 = 1 << 1;
    /// Area created by `vmap()` — mapping existing pages.
    pub const VM_MAP: u32 = 1 << 2;
    /// Area mappable into user space.
    pub const VM_USERMAP: u32 = 1 << 3;
    /// Area uses DMA-coherent memory.
    pub const VM_DMA_COHERENT: u32 = 1 << 4;
    /// Area is lazily freed (delayed via RCU).
    pub const VM_LAZY_FREE: u32 = 1 << 5;
    /// Area has been unmapped but not yet flushed.
    pub const VM_FLUSH_PENDING: u32 = 1 << 6;
}

// -------------------------------------------------------------------
// VmallocRemapArea
// -------------------------------------------------------------------

/// Descriptor for a vmalloc remap area.
///
/// Each area tracks a base virtual address, the backing physical
/// pages, and type flags.
#[derive(Clone)]
pub struct VmallocRemapArea {
    /// Base virtual address in kernel space.
    base_vaddr: u64,
    /// Number of pages in this area.
    nr_pages: usize,
    /// Physical page frame numbers (PFNs) backing this area.
    pages: [u64; MAX_PAGES_PER_AREA],
    /// Total size in bytes (nr_pages * PAGE_SIZE + guard).
    total_size: u64,
    /// Area type flags.
    flags: u32,
    /// Whether this area is active.
    active: bool,
    /// Unique area ID.
    area_id: u32,
    /// Caller-provided tag for debugging.
    caller_addr: u64,
}

impl VmallocRemapArea {
    /// Create an empty area descriptor.
    const fn empty() -> Self {
        Self {
            base_vaddr: 0,
            nr_pages: 0,
            pages: [0u64; MAX_PAGES_PER_AREA],
            total_size: 0,
            flags: 0,
            active: false,
            area_id: 0,
            caller_addr: 0,
        }
    }

    /// Return the base virtual address.
    pub const fn base_vaddr(&self) -> u64 {
        self.base_vaddr
    }

    /// Return the number of pages.
    pub const fn nr_pages(&self) -> usize {
        self.nr_pages
    }

    /// Return the area flags.
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Return the total size including guard page.
    pub const fn total_size(&self) -> u64 {
        self.total_size
    }

    /// Return the area ID.
    pub const fn area_id(&self) -> u32 {
        self.area_id
    }

    /// Return the physical pages backing this area.
    pub fn phys_pages(&self) -> &[u64] {
        &self.pages[..self.nr_pages]
    }

    /// Whether this area is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Whether this is an ioremap area.
    pub const fn is_ioremap(&self) -> bool {
        self.flags & VmAreaFlags::VM_IOREMAP != 0
    }

    /// Whether this area is lazily freed.
    pub const fn is_lazy_free(&self) -> bool {
        self.flags & VmAreaFlags::VM_LAZY_FREE != 0
    }
}

// -------------------------------------------------------------------
// LazyFlushEntry
// -------------------------------------------------------------------

/// Entry in the lazy TLB flush queue.
#[derive(Clone, Copy)]
struct LazyFlushEntry {
    /// Virtual address to flush.
    vaddr: u64,
    /// Number of pages to flush.
    nr_pages: usize,
    /// Whether this entry is pending.
    pending: bool,
}

impl LazyFlushEntry {
    /// Create an empty entry.
    const fn empty() -> Self {
        Self {
            vaddr: 0,
            nr_pages: 0,
            pending: false,
        }
    }
}

// -------------------------------------------------------------------
// VmapBlock
// -------------------------------------------------------------------

/// A pre-allocated vmap block for fast per-CPU vmap operations.
#[derive(Clone, Copy)]
struct VmapBlock {
    /// Base virtual address of this block.
    base_vaddr: u64,
    /// Number of pages in the block.
    nr_pages: usize,
    /// Bitmap of used pages (up to 64 pages per block).
    used_bitmap: u64,
    /// Whether this block is active.
    active: bool,
}

impl VmapBlock {
    /// Create an empty block.
    const fn empty() -> Self {
        Self {
            base_vaddr: 0,
            nr_pages: 0,
            used_bitmap: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// VmapBlockCache
// -------------------------------------------------------------------

/// Per-CPU vmap block cache for fast small mappings.
#[derive(Clone)]
struct VmapBlockCache {
    /// Cached blocks.
    blocks: [VmapBlock; VMAP_BLOCKS_PER_CPU],
    /// Number of active blocks.
    active_count: usize,
}

impl VmapBlockCache {
    /// Create an empty cache.
    const fn empty() -> Self {
        Self {
            blocks: [const { VmapBlock::empty() }; VMAP_BLOCKS_PER_CPU],
            active_count: 0,
        }
    }
}

// -------------------------------------------------------------------
// VmallocRemapStats
// -------------------------------------------------------------------

/// Statistics for vmalloc remap operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmallocRemapStats {
    /// Total vmap calls.
    pub vmap_count: u64,
    /// Total vunmap calls.
    pub vunmap_count: u64,
    /// Total ioremap calls.
    pub ioremap_count: u64,
    /// Total iounmap calls.
    pub iounmap_count: u64,
    /// Total remap_vmalloc_range calls.
    pub remap_count: u64,
    /// Total lazy TLB flushes.
    pub lazy_flush_count: u64,
    /// Total RCU-delayed frees.
    pub rcu_free_count: u64,
    /// Currently active areas.
    pub active_areas: u32,
    /// Total pages currently mapped.
    pub total_mapped_pages: u64,
}

// -------------------------------------------------------------------
// VmallocRemapper
// -------------------------------------------------------------------

/// Central vmalloc remap manager.
///
/// Manages remap area allocation, vmap/vunmap, ioremap/iounmap,
/// user-space remapping, and lazy TLB flush.
pub struct VmallocRemapper {
    /// Remap area array.
    areas: [VmallocRemapArea; MAX_REMAP_AREAS],
    /// Per-CPU vmap block caches.
    percpu_cache: [VmapBlockCache; NR_CPUS],
    /// Lazy TLB flush queue.
    lazy_flush: [LazyFlushEntry; MAX_LAZY_FLUSH],
    /// Number of pending lazy flushes.
    lazy_flush_count: usize,
    /// Next area ID.
    next_id: u32,
    /// Next virtual address to allocate.
    next_vaddr: u64,
    /// Statistics.
    stats: VmallocRemapStats,
}

impl VmallocRemapper {
    /// Create a new remapper.
    pub const fn new() -> Self {
        Self {
            areas: [const { VmallocRemapArea::empty() }; MAX_REMAP_AREAS],
            percpu_cache: [const { VmapBlockCache::empty() }; NR_CPUS],
            lazy_flush: [const { LazyFlushEntry::empty() }; MAX_LAZY_FLUSH],
            lazy_flush_count: 0,
            next_id: 1,
            next_vaddr: VMALLOC_START,
            stats: VmallocRemapStats {
                vmap_count: 0,
                vunmap_count: 0,
                ioremap_count: 0,
                iounmap_count: 0,
                remap_count: 0,
                lazy_flush_count: 0,
                rcu_free_count: 0,
                active_areas: 0,
                total_mapped_pages: 0,
            },
        }
    }

    /// Find a free area slot.
    fn find_free_slot(&self) -> Result<usize> {
        for i in 0..MAX_REMAP_AREAS {
            if !self.areas[i].active {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find an area by its base virtual address.
    fn find_by_vaddr(&self, vaddr: u64) -> Result<usize> {
        for i in 0..MAX_REMAP_AREAS {
            if self.areas[i].active && self.areas[i].base_vaddr == vaddr {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    /// Find an area by its ID.
    fn find_by_id(&self, area_id: u32) -> Result<usize> {
        for i in 0..MAX_REMAP_AREAS {
            if self.areas[i].active && self.areas[i].area_id == area_id {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    /// Allocate a virtual address range.
    fn alloc_vaddr(&mut self, nr_pages: usize) -> Result<u64> {
        let size = (nr_pages as u64) * PAGE_SIZE + GUARD_SIZE;
        let vaddr = self.next_vaddr;
        if vaddr + size > VMALLOC_END {
            return Err(Error::OutOfMemory);
        }
        self.next_vaddr = vaddr + size;
        Ok(vaddr)
    }

    /// Map arbitrary physical pages into kernel virtual address space.
    ///
    /// # Arguments
    /// - `phys_pages` — slice of physical page frame numbers.
    /// - `flags` — additional area flags (VM_MAP is always set).
    ///
    /// Returns the base virtual address of the mapping.
    ///
    /// # Errors
    /// - `InvalidArgument` — empty or too many pages.
    /// - `OutOfMemory` — no free area slots or VA space.
    pub fn vmap(&mut self, phys_pages: &[u64], flags: u32) -> Result<u64> {
        let nr = phys_pages.len();
        if nr == 0 || nr > MAX_PAGES_PER_AREA {
            return Err(Error::InvalidArgument);
        }

        let slot = self.find_free_slot()?;
        let vaddr = self.alloc_vaddr(nr)?;
        let area_id = self.next_id;
        self.next_id += 1;

        self.areas[slot].base_vaddr = vaddr;
        self.areas[slot].nr_pages = nr;
        self.areas[slot].pages[..nr].copy_from_slice(phys_pages);
        self.areas[slot].total_size = (nr as u64) * PAGE_SIZE + GUARD_SIZE;
        self.areas[slot].flags = flags | VmAreaFlags::VM_MAP;
        self.areas[slot].active = true;
        self.areas[slot].area_id = area_id;

        self.stats.vmap_count += 1;
        self.stats.active_areas += 1;
        self.stats.total_mapped_pages += nr as u64;

        Ok(vaddr)
    }

    /// Unmap a previously vmap'd area.
    ///
    /// If `lazy` is true, the TLB flush is deferred (lazy free).
    ///
    /// # Errors
    /// - `NotFound` — no area at this virtual address.
    pub fn vunmap(&mut self, vaddr: u64, lazy: bool) -> Result<()> {
        let slot = self.find_by_vaddr(vaddr)?;

        if lazy {
            // Defer TLB flush.
            self.areas[slot].flags |= VmAreaFlags::VM_LAZY_FREE | VmAreaFlags::VM_FLUSH_PENDING;
            self.add_lazy_flush(vaddr, self.areas[slot].nr_pages);
        } else {
            let nr = self.areas[slot].nr_pages;
            self.areas[slot] = VmallocRemapArea::empty();
            self.stats.active_areas = self.stats.active_areas.saturating_sub(1);
            self.stats.total_mapped_pages = self.stats.total_mapped_pages.saturating_sub(nr as u64);
        }

        self.stats.vunmap_count += 1;
        Ok(())
    }

    /// Map an MMIO region into kernel virtual address space.
    ///
    /// # Arguments
    /// - `phys_addr` — physical base address (page-aligned).
    /// - `nr_pages` — number of pages to map.
    ///
    /// Returns the base virtual address.
    ///
    /// # Errors
    /// - `InvalidArgument` — phys_addr not page-aligned or nr_pages=0.
    /// - `OutOfMemory` — no free slots or VA space.
    pub fn ioremap(&mut self, phys_addr: u64, nr_pages: usize) -> Result<u64> {
        if phys_addr % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        if nr_pages == 0 || nr_pages > MAX_PAGES_PER_AREA {
            return Err(Error::InvalidArgument);
        }

        let slot = self.find_free_slot()?;
        let vaddr = self.alloc_vaddr(nr_pages)?;
        let area_id = self.next_id;
        self.next_id += 1;

        // Build page array from contiguous physical range.
        for i in 0..nr_pages {
            self.areas[slot].pages[i] = phys_addr / PAGE_SIZE + i as u64;
        }
        self.areas[slot].base_vaddr = vaddr;
        self.areas[slot].nr_pages = nr_pages;
        self.areas[slot].total_size = (nr_pages as u64) * PAGE_SIZE + GUARD_SIZE;
        self.areas[slot].flags = VmAreaFlags::VM_IOREMAP;
        self.areas[slot].active = true;
        self.areas[slot].area_id = area_id;

        self.stats.ioremap_count += 1;
        self.stats.active_areas += 1;
        self.stats.total_mapped_pages += nr_pages as u64;

        Ok(vaddr)
    }

    /// Unmap an ioremap'd area.
    ///
    /// # Errors
    /// - `NotFound` — no area at this virtual address.
    /// - `InvalidArgument` — area is not an ioremap area.
    pub fn iounmap(&mut self, vaddr: u64) -> Result<()> {
        let slot = self.find_by_vaddr(vaddr)?;
        if self.areas[slot].flags & VmAreaFlags::VM_IOREMAP == 0 {
            return Err(Error::InvalidArgument);
        }

        let nr = self.areas[slot].nr_pages;
        self.areas[slot] = VmallocRemapArea::empty();

        self.stats.iounmap_count += 1;
        self.stats.active_areas = self.stats.active_areas.saturating_sub(1);
        self.stats.total_mapped_pages = self.stats.total_mapped_pages.saturating_sub(nr as u64);

        Ok(())
    }

    /// Remap a vmalloc area into a user virtual memory area.
    ///
    /// Maps the pages of a kernel vmalloc area into user space
    /// at the given user virtual address.
    ///
    /// Returns the number of pages remapped.
    ///
    /// # Errors
    /// - `NotFound` — no vmalloc area at kernel_vaddr.
    /// - `InvalidArgument` — area is ioremap (not user-mappable).
    pub fn remap_vmalloc_range(&mut self, kernel_vaddr: u64, _user_vaddr: u64) -> Result<usize> {
        let slot = self.find_by_vaddr(kernel_vaddr)?;
        if self.areas[slot].flags & VmAreaFlags::VM_IOREMAP != 0 {
            return Err(Error::InvalidArgument);
        }

        // Mark area as user-mappable.
        self.areas[slot].flags |= VmAreaFlags::VM_USERMAP;
        let nr = self.areas[slot].nr_pages;

        self.stats.remap_count += 1;
        Ok(nr)
    }

    /// Map a range of physical pages into kernel VA (ioremap_page_range).
    ///
    /// Similar to ioremap but allows non-contiguous physical pages
    /// and sets VM_MAP instead of VM_IOREMAP.
    ///
    /// # Errors
    /// - `InvalidArgument` — empty pages or too many.
    /// - `OutOfMemory` — no free slots.
    pub fn ioremap_page_range(&mut self, phys_pages: &[u64]) -> Result<u64> {
        let nr = phys_pages.len();
        if nr == 0 || nr > MAX_PAGES_PER_AREA {
            return Err(Error::InvalidArgument);
        }

        let slot = self.find_free_slot()?;
        let vaddr = self.alloc_vaddr(nr)?;
        let area_id = self.next_id;
        self.next_id += 1;

        self.areas[slot].base_vaddr = vaddr;
        self.areas[slot].nr_pages = nr;
        self.areas[slot].pages[..nr].copy_from_slice(phys_pages);
        self.areas[slot].total_size = (nr as u64) * PAGE_SIZE + GUARD_SIZE;
        self.areas[slot].flags = VmAreaFlags::VM_IOREMAP | VmAreaFlags::VM_MAP;
        self.areas[slot].active = true;
        self.areas[slot].area_id = area_id;

        self.stats.ioremap_count += 1;
        self.stats.active_areas += 1;
        self.stats.total_mapped_pages += nr as u64;

        Ok(vaddr)
    }

    /// Delayed free via RCU-like mechanism (vfree).
    ///
    /// Marks the area for lazy free and queues a TLB flush.
    ///
    /// # Errors
    /// - `NotFound` — no area at this virtual address.
    pub fn vfree_rcu(&mut self, vaddr: u64) -> Result<()> {
        let slot = self.find_by_vaddr(vaddr)?;
        self.areas[slot].flags |= VmAreaFlags::VM_LAZY_FREE;
        self.add_lazy_flush(vaddr, self.areas[slot].nr_pages);
        self.stats.rcu_free_count += 1;
        Ok(())
    }

    /// Add an entry to the lazy TLB flush queue.
    fn add_lazy_flush(&mut self, vaddr: u64, nr_pages: usize) {
        if self.lazy_flush_count < MAX_LAZY_FLUSH {
            self.lazy_flush[self.lazy_flush_count] = LazyFlushEntry {
                vaddr,
                nr_pages,
                pending: true,
            };
            self.lazy_flush_count += 1;
        } else {
            // Queue full — force immediate flush.
            self.flush_lazy_tlb();
            if self.lazy_flush_count < MAX_LAZY_FLUSH {
                self.lazy_flush[self.lazy_flush_count] = LazyFlushEntry {
                    vaddr,
                    nr_pages,
                    pending: true,
                };
                self.lazy_flush_count += 1;
            }
        }
    }

    /// Flush all pending lazy TLB entries.
    ///
    /// Frees the areas and clears the flush queue.
    /// Returns the number of areas flushed.
    pub fn flush_lazy_tlb(&mut self) -> usize {
        let mut flushed = 0;
        for i in 0..self.lazy_flush_count {
            if !self.lazy_flush[i].pending {
                continue;
            }
            let vaddr = self.lazy_flush[i].vaddr;
            if let Ok(slot) = self.find_by_vaddr(vaddr) {
                let nr = self.areas[slot].nr_pages;
                self.areas[slot] = VmallocRemapArea::empty();
                self.stats.active_areas = self.stats.active_areas.saturating_sub(1);
                self.stats.total_mapped_pages =
                    self.stats.total_mapped_pages.saturating_sub(nr as u64);
                flushed += 1;
            }
            self.lazy_flush[i].pending = false;
        }
        self.lazy_flush_count = 0;
        self.stats.lazy_flush_count += flushed as u64;
        flushed
    }

    /// Allocate from per-CPU vmap block cache.
    ///
    /// Returns the virtual address if a block has space, or
    /// `OutOfMemory` if the cache is empty.
    pub fn alloc_vmap_block(&mut self, cpu: usize, nr_pages: usize) -> Result<u64> {
        let cpu_idx = cpu % NR_CPUS;
        for b in 0..VMAP_BLOCKS_PER_CPU {
            let block = &mut self.percpu_cache[cpu_idx].blocks[b];
            if !block.active {
                continue;
            }
            // Find nr_pages contiguous free bits.
            if let Some(start) = Self::find_free_bits(block.used_bitmap, block.nr_pages, nr_pages) {
                // Mark bits as used.
                for bit in start..start + nr_pages {
                    block.used_bitmap |= 1u64 << bit;
                }
                return Ok(block.base_vaddr + (start as u64) * PAGE_SIZE);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find `count` contiguous zero bits in a bitmap.
    fn find_free_bits(bitmap: u64, total: usize, count: usize) -> Option<usize> {
        if count == 0 || count > total || total > 64 {
            return None;
        }
        let mut run = 0;
        let mut start = 0;
        for i in 0..total {
            if bitmap & (1u64 << i) == 0 {
                if run == 0 {
                    start = i;
                }
                run += 1;
                if run >= count {
                    return Some(start);
                }
            } else {
                run = 0;
            }
        }
        None
    }

    /// Initialise a per-CPU vmap block.
    ///
    /// # Errors
    /// - `OutOfMemory` — per-CPU cache full or VA exhausted.
    pub fn init_vmap_block(&mut self, cpu: usize, nr_pages: usize) -> Result<u64> {
        let cpu_idx = cpu % NR_CPUS;
        if self.percpu_cache[cpu_idx].active_count >= VMAP_BLOCKS_PER_CPU {
            return Err(Error::OutOfMemory);
        }
        let vaddr = self.alloc_vaddr(nr_pages)?;
        for b in 0..VMAP_BLOCKS_PER_CPU {
            if !self.percpu_cache[cpu_idx].blocks[b].active {
                self.percpu_cache[cpu_idx].blocks[b] = VmapBlock {
                    base_vaddr: vaddr,
                    nr_pages,
                    used_bitmap: 0,
                    active: true,
                };
                self.percpu_cache[cpu_idx].active_count += 1;
                return Ok(vaddr);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up an area by virtual address.
    ///
    /// # Errors
    /// - `NotFound` — no area contains this address.
    pub fn find_area(&self, vaddr: u64) -> Result<&VmallocRemapArea> {
        for i in 0..MAX_REMAP_AREAS {
            if !self.areas[i].active {
                continue;
            }
            let base = self.areas[i].base_vaddr;
            let end = base + self.areas[i].total_size;
            if vaddr >= base && vaddr < end {
                return Ok(&self.areas[i]);
            }
        }
        Err(Error::NotFound)
    }

    /// Return current statistics.
    pub const fn stats(&self) -> &VmallocRemapStats {
        &self.stats
    }

    /// Return the number of active areas.
    pub const fn active_areas(&self) -> u32 {
        self.stats.active_areas
    }

    /// Check whether an address falls within the vmalloc range.
    pub const fn is_vmalloc_addr(addr: u64) -> bool {
        addr >= VMALLOC_START && addr <= VMALLOC_END
    }
}
