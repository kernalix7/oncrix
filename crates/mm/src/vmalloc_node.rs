// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NUMA-aware vmalloc.
//!
//! Allocates virtually contiguous (physically non-contiguous) kernel
//! memory with a preferred NUMA node. Each NUMA node maintains its
//! own sorted list of vmap areas for fast lookup and insertion. Lazy
//! TLB flush is performed on vfree to amortise flush overhead.
//!
//! # Key Types
//!
//! - [`VmapArea`] — descriptor for one vmalloc region
//! - [`NodeVmapList`] — per-node sorted vmap area list
//! - [`VmallocNodeStats`] — per-node allocation statistics
//! - [`LazyTlbFlush`] — pending lazy TLB flush state
//! - [`VmallocNodeAllocator`] — top-level NUMA-aware allocator
//!
//! Reference: Linux `mm/vmalloc.c` (`vmalloc_node`,
//! `__vmalloc_node_range`, `vmap_area`), `include/linux/vmalloc.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Start of the vmalloc virtual address range.
const VMALLOC_START: u64 = 0xFFFF_C900_0000_0000;

/// End of the vmalloc virtual address range.
const VMALLOC_END: u64 = 0xFFFF_E8FF_FFFF_FFFF;

/// Guard page size appended after each allocation.
const GUARD_SIZE: u64 = PAGE_SIZE;

/// Maximum vmap areas per NUMA node.
const MAX_AREAS_PER_NODE: usize = 128;

/// Maximum physical pages per vmap area.
const MAX_PAGES_PER_AREA: usize = 64;

/// Maximum NUMA nodes.
const MAX_NUMA_NODES: usize = 4;

/// Maximum pending lazy TLB flushes.
const MAX_LAZY_FLUSH: usize = 64;

// -------------------------------------------------------------------
// VmapArea
// -------------------------------------------------------------------

/// Descriptor for a single vmalloc region.
#[derive(Clone, Copy)]
pub struct VmapArea {
    /// Virtual base address.
    pub base: u64,
    /// Total size in bytes (allocation + guard).
    pub size: u64,
    /// Number of physical pages backing this area.
    pub nr_pages: usize,
    /// Physical page addresses (per-page).
    pub phys_pages: [u64; MAX_PAGES_PER_AREA],
    /// NUMA node that was preferred for this allocation.
    pub preferred_node: u16,
    /// Caller address that requested this allocation.
    pub caller: u64,
    /// Unique area identifier.
    pub id: u32,
    /// Whether this area is active.
    pub active: bool,
}

impl VmapArea {
    /// Create an empty, inactive vmap area.
    const fn empty() -> Self {
        Self {
            base: 0,
            size: 0,
            nr_pages: 0,
            phys_pages: [0u64; MAX_PAGES_PER_AREA],
            preferred_node: 0,
            caller: 0,
            id: 0,
            active: false,
        }
    }

    /// Virtual end address (base + size).
    pub const fn end(&self) -> u64 {
        self.base + self.size
    }
}

// -------------------------------------------------------------------
// NodeVmapList
// -------------------------------------------------------------------

/// Per-NUMA-node sorted list of vmap areas.
///
/// Areas are kept sorted by virtual base address to allow binary
/// search lookup and gap finding.
pub struct NodeVmapList {
    /// NUMA node identifier.
    pub node_id: u16,
    /// Sorted array of vmap areas.
    areas: [VmapArea; MAX_AREAS_PER_NODE],
    /// Number of active areas.
    count: usize,
    /// Next virtual address to hand out on this node.
    next_addr: u64,
}

impl NodeVmapList {
    /// Create an empty vmap list for a node.
    const fn new(node_id: u16, base_addr: u64) -> Self {
        Self {
            node_id,
            areas: [const { VmapArea::empty() }; MAX_AREAS_PER_NODE],
            count: 0,
            next_addr: base_addr,
        }
    }

    /// Number of active areas.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Look up an area by virtual base address.
    pub fn find_by_addr(&self, addr: u64) -> Option<&VmapArea> {
        self.areas[..self.count]
            .iter()
            .find(|a| a.active && a.base == addr)
    }

    /// Insert a new area, maintaining sort order.
    fn insert(&mut self, area: VmapArea) -> Result<usize> {
        if self.count >= MAX_AREAS_PER_NODE {
            return Err(Error::OutOfMemory);
        }
        // Find insertion point (sorted by base address).
        let pos = self.areas[..self.count]
            .iter()
            .position(|a| a.base > area.base)
            .unwrap_or(self.count);

        // Shift elements to make room.
        let mut i = self.count;
        while i > pos {
            self.areas[i] = self.areas[i - 1];
            i -= 1;
        }
        self.areas[pos] = area;
        self.count += 1;
        Ok(pos)
    }

    /// Remove an area by virtual base address.
    fn remove(&mut self, addr: u64) -> Result<VmapArea> {
        let pos = self.areas[..self.count]
            .iter()
            .position(|a| a.active && a.base == addr)
            .ok_or(Error::NotFound)?;

        let removed = self.areas[pos];
        // Shift remaining elements.
        let mut i = pos;
        while i + 1 < self.count {
            self.areas[i] = self.areas[i + 1];
            i += 1;
        }
        self.areas[self.count - 1] = VmapArea::empty();
        self.count -= 1;
        Ok(removed)
    }

    /// Allocate a virtual address range of the given size.
    fn alloc_va(&mut self, total_size: u64) -> Result<u64> {
        if self
            .next_addr
            .checked_add(total_size)
            .is_none_or(|end| end > VMALLOC_END)
        {
            return Err(Error::OutOfMemory);
        }
        let addr = self.next_addr;
        self.next_addr += total_size;
        Ok(addr)
    }
}

// -------------------------------------------------------------------
// VmallocNodeStats
// -------------------------------------------------------------------

/// Per-node vmalloc statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmallocNodeStats {
    /// Active areas on this node.
    pub active_areas: usize,
    /// Total pages allocated on this node.
    pub total_pages: usize,
    /// Total bytes allocated on this node.
    pub total_bytes: u64,
    /// Allocations performed on this node.
    pub alloc_count: u64,
    /// Frees performed on this node.
    pub free_count: u64,
}

// -------------------------------------------------------------------
// LazyTlbFlush
// -------------------------------------------------------------------

/// A pending lazy TLB flush entry.
#[derive(Debug, Clone, Copy)]
pub struct LazyTlbFlush {
    /// Virtual base address to flush.
    pub base: u64,
    /// Size of the range to flush.
    pub size: u64,
    /// Whether this entry is pending.
    active: bool,
}

impl LazyTlbFlush {
    /// Empty flush entry.
    const fn empty() -> Self {
        Self {
            base: 0,
            size: 0,
            active: false,
        }
    }
}

/// Lazy TLB flush manager.
pub struct LazyTlbFlushQueue {
    /// Pending flushes.
    entries: [LazyTlbFlush; MAX_LAZY_FLUSH],
    /// Number of pending entries.
    count: usize,
    /// Total flushes performed.
    total_flushed: u64,
}

impl LazyTlbFlushQueue {
    /// Create an empty flush queue.
    const fn new() -> Self {
        Self {
            entries: [LazyTlbFlush::empty(); MAX_LAZY_FLUSH],
            count: 0,
            total_flushed: 0,
        }
    }

    /// Enqueue a lazy flush. If the queue is full, force a
    /// drain first.
    fn enqueue(&mut self, base: u64, size: u64) {
        if self.count >= MAX_LAZY_FLUSH {
            self.drain();
        }
        self.entries[self.count] = LazyTlbFlush {
            base,
            size,
            active: true,
        };
        self.count += 1;
    }

    /// Drain (execute) all pending TLB flushes.
    pub fn drain(&mut self) -> u64 {
        let flushed = self.count as u64;
        for e in &mut self.entries[..self.count] {
            e.active = false;
        }
        self.count = 0;
        self.total_flushed += flushed;
        flushed
    }

    /// Number of pending flushes.
    pub const fn pending(&self) -> usize {
        self.count
    }

    /// Total flushes performed.
    pub const fn total_flushed(&self) -> u64 {
        self.total_flushed
    }
}

// -------------------------------------------------------------------
// VmallocNodeAllocator
// -------------------------------------------------------------------

/// Top-level NUMA-aware vmalloc allocator.
///
/// Distributes vmalloc areas across NUMA nodes based on the
/// caller's preferred node, falling back to other nodes when the
/// preferred one is exhausted.
pub struct VmallocNodeAllocator {
    /// Per-node vmap area lists.
    nodes: [NodeVmapList; MAX_NUMA_NODES],
    /// Number of active NUMA nodes.
    active_nodes: usize,
    /// Next unique area identifier.
    next_id: u32,
    /// Per-node statistics.
    node_stats: [VmallocNodeStats; MAX_NUMA_NODES],
    /// Lazy TLB flush queue.
    flush_queue: LazyTlbFlushQueue,
}

impl Default for VmallocNodeAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl VmallocNodeAllocator {
    /// Create a new allocator with address space divided among
    /// nodes.
    pub const fn new() -> Self {
        // Each node gets a 1 TiB slice of the vmalloc range.
        const SLICE: u64 = 0x0000_0100_0000_0000; // 1 TiB
        Self {
            nodes: [
                NodeVmapList::new(0, VMALLOC_START),
                NodeVmapList::new(1, VMALLOC_START + SLICE),
                NodeVmapList::new(2, VMALLOC_START + SLICE * 2),
                NodeVmapList::new(3, VMALLOC_START + SLICE * 3),
            ],
            active_nodes: 1,
            next_id: 1,
            node_stats: [const {
                VmallocNodeStats {
                    active_areas: 0,
                    total_pages: 0,
                    total_bytes: 0,
                    alloc_count: 0,
                    free_count: 0,
                }
            }; MAX_NUMA_NODES],
            flush_queue: LazyTlbFlushQueue::new(),
        }
    }

    /// Set the number of active NUMA nodes.
    pub fn set_active_nodes(&mut self, count: usize) -> Result<()> {
        if count == 0 || count > MAX_NUMA_NODES {
            return Err(Error::InvalidArgument);
        }
        self.active_nodes = count;
        Ok(())
    }

    /// Allocate virtually contiguous memory on the preferred
    /// NUMA node. Falls back to other nodes on failure.
    pub fn vmalloc_node(&mut self, size: u64, preferred_node: u16) -> Result<u64> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        let nr_pages = pages_for(size);
        if nr_pages > MAX_PAGES_PER_AREA {
            return Err(Error::InvalidArgument);
        }
        let total_size = (nr_pages as u64) * PAGE_SIZE + GUARD_SIZE;

        // Try preferred node first.
        let node_id = (preferred_node as usize).min(self.active_nodes.saturating_sub(1));
        let result = self.try_alloc_on_node(node_id, total_size, nr_pages, preferred_node);
        if result.is_ok() {
            return result;
        }

        // Fallback: try other nodes in distance order.
        for n in 0..self.active_nodes {
            if n == node_id {
                continue;
            }
            let r = self.try_alloc_on_node(n, total_size, nr_pages, preferred_node);
            if r.is_ok() {
                return r;
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Free a vmalloc area by virtual address. Enqueues a lazy
    /// TLB flush.
    pub fn vfree(&mut self, addr: u64) -> Result<()> {
        for n in 0..self.active_nodes {
            if self.nodes[n].find_by_addr(addr).is_some() {
                let removed = self.nodes[n].remove(addr)?;
                self.node_stats[n].active_areas = self.node_stats[n].active_areas.saturating_sub(1);
                self.node_stats[n].total_pages = self.node_stats[n]
                    .total_pages
                    .saturating_sub(removed.nr_pages);
                self.node_stats[n].total_bytes =
                    self.node_stats[n].total_bytes.saturating_sub(removed.size);
                self.node_stats[n].free_count += 1;

                // Lazy TLB flush.
                self.flush_queue.enqueue(removed.base, removed.size);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Force-drain all pending lazy TLB flushes.
    pub fn flush_tlb(&mut self) -> u64 {
        self.flush_queue.drain()
    }

    /// Number of pending lazy TLB flushes.
    pub const fn pending_flushes(&self) -> usize {
        self.flush_queue.pending()
    }

    /// Per-node statistics.
    pub fn node_stats(&self, node: usize) -> Result<&VmallocNodeStats> {
        if node >= self.active_nodes {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.node_stats[node])
    }

    /// Total areas across all nodes.
    pub fn total_areas(&self) -> usize {
        self.node_stats[..self.active_nodes]
            .iter()
            .map(|s| s.active_areas)
            .sum()
    }

    /// Try to allocate on a specific node.
    fn try_alloc_on_node(
        &mut self,
        node: usize,
        total_size: u64,
        nr_pages: usize,
        preferred_node: u16,
    ) -> Result<u64> {
        let base = self.nodes[node].alloc_va(total_size)?;
        let area_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let mut area = VmapArea::empty();
        area.base = base;
        area.size = total_size;
        area.nr_pages = nr_pages;
        area.preferred_node = preferred_node;
        area.id = area_id;
        area.active = true;

        // Simulate physical page allocation.
        for i in 0..nr_pages {
            area.phys_pages[i] = base + (i as u64) * PAGE_SIZE; // placeholder
        }

        self.nodes[node].insert(area)?;

        self.node_stats[node].active_areas += 1;
        self.node_stats[node].total_pages += nr_pages;
        self.node_stats[node].total_bytes += total_size;
        self.node_stats[node].alloc_count += 1;
        Ok(base)
    }
}

/// Compute the number of pages needed for a byte size.
const fn pages_for(size: u64) -> usize {
    ((size + PAGE_SIZE - 1) / PAGE_SIZE) as usize
}
