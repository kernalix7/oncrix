// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Huge page (hugetlb) allocator for the ONCRIX memory manager.
//!
//! Manages pre-reserved pools of huge pages (2 MiB and 1 GiB) with
//! per-NUMA-node allocation and free-list management. Unlike
//! transparent huge pages (THP), hugetlb pages are explicitly reserved
//! at boot or runtime and are never subject to compaction or reclaim.
//!
//! # Subsystems
//!
//! - [`HugePageOrder`] — size classification (2 MiB / 1 GiB)
//! - [`HugePage`] — descriptor for a single reserved huge page
//! - [`NodeReserve`] — per-NUMA-node reservation pool
//! - [`HugetlbPool`] — global hugetlb pool with per-node reserves
//! - [`HugetlbMeminfo`] — `/proc/meminfo` hugetlb fields
//! - [`HugetlbStats`] — allocation statistics
//!
//! Reference: Linux `mm/hugetlb.c`, `include/linux/hugetlb.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// 2 MiB huge page size in bytes.
const HUGE_2M: u64 = 2 * 1024 * 1024;

/// 1 GiB huge page size in bytes.
const HUGE_1G: u64 = 1024 * 1024 * 1024;

/// Maximum NUMA nodes.
const MAX_NUMA_NODES: usize = 8;

/// Maximum huge pages per node (2 MiB pool).
const MAX_PAGES_PER_NODE_2M: usize = 1024;

/// Maximum huge pages per node (1 GiB pool).
const MAX_PAGES_PER_NODE_1G: usize = 8;

/// Maximum total huge pages across all nodes.
const MAX_TOTAL_PAGES: usize = MAX_NUMA_NODES * MAX_PAGES_PER_NODE_2M;

/// Free list sentinel — no next page.
const FREE_LIST_END: u32 = u32::MAX;

// -------------------------------------------------------------------
// HugePageOrder
// -------------------------------------------------------------------

/// Huge page size classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HugePageOrder {
    /// 2 MiB (order 9, 512 base pages).
    Order2M,
    /// 1 GiB (order 18, 262144 base pages).
    Order1G,
}

impl HugePageOrder {
    /// Returns the size in bytes.
    pub const fn size_bytes(self) -> u64 {
        match self {
            Self::Order2M => HUGE_2M,
            Self::Order1G => HUGE_1G,
        }
    }

    /// Returns the number of base 4 KiB pages in this huge page.
    pub const fn nr_base_pages(self) -> u64 {
        self.size_bytes() / PAGE_SIZE
    }

    /// Returns the allocation order (log2 of page count).
    pub const fn order(self) -> u32 {
        match self {
            Self::Order2M => 9,
            Self::Order1G => 18,
        }
    }
}

impl Default for HugePageOrder {
    fn default() -> Self {
        Self::Order2M
    }
}

// -------------------------------------------------------------------
// HugePageState
// -------------------------------------------------------------------

/// State of a huge page in the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HugePageState {
    /// Page is free and available for allocation.
    #[default]
    Free,
    /// Page is allocated and in use.
    Allocated,
    /// Page is reserved but not yet backed by physical memory.
    Reserved,
    /// Page is being migrated.
    Migrating,
}

// -------------------------------------------------------------------
// HugePage
// -------------------------------------------------------------------

/// Descriptor for a single reserved huge page.
#[derive(Debug, Clone, Copy)]
pub struct HugePage {
    /// Physical frame number (base page aligned).
    pfn: u64,
    /// Size order of this huge page.
    order: HugePageOrder,
    /// Current state.
    state: HugePageState,
    /// NUMA node this page belongs to.
    node_id: u8,
    /// Reference count (number of mappings).
    refcount: u32,
    /// Index of next free page in free list (FREE_LIST_END if tail).
    next_free: u32,
    /// Generation counter for ABA prevention.
    generation: u64,
}

impl HugePage {
    /// Creates a new huge page descriptor.
    pub const fn new(pfn: u64, order: HugePageOrder, node_id: u8) -> Self {
        Self {
            pfn,
            order,
            state: HugePageState::Free,
            node_id,
            refcount: 0,
            next_free: FREE_LIST_END,
            generation: 0,
        }
    }

    /// Returns the physical frame number.
    pub const fn pfn(&self) -> u64 {
        self.pfn
    }

    /// Returns the physical address.
    pub const fn phys_addr(&self) -> u64 {
        self.pfn * PAGE_SIZE
    }

    /// Returns the huge page order.
    pub const fn order(&self) -> HugePageOrder {
        self.order
    }

    /// Returns the current state.
    pub const fn state(&self) -> HugePageState {
        self.state
    }

    /// Returns the NUMA node ID.
    pub const fn node_id(&self) -> u8 {
        self.node_id
    }

    /// Returns the current reference count.
    pub const fn refcount(&self) -> u32 {
        self.refcount
    }

    /// Increments the reference count.
    pub fn get(&mut self) {
        self.refcount = self.refcount.saturating_add(1);
    }

    /// Decrements the reference count. Returns true if it reached zero.
    pub fn put(&mut self) -> bool {
        self.refcount = self.refcount.saturating_sub(1);
        self.refcount == 0
    }
}

impl Default for HugePage {
    fn default() -> Self {
        Self::new(0, HugePageOrder::Order2M, 0)
    }
}

// -------------------------------------------------------------------
// NodeReserve
// -------------------------------------------------------------------

/// Per-NUMA-node reservation pool for 2 MiB huge pages.
#[derive(Debug)]
pub struct NodeReserve {
    /// NUMA node identifier.
    node_id: u8,
    /// Pages in this node's pool.
    pages_2m: [HugePage; MAX_PAGES_PER_NODE_2M],
    /// Number of allocated pages in the pool.
    count_2m: usize,
    /// Head of the 2M free list (index into pages_2m).
    free_head_2m: u32,
    /// Number of free 2M pages.
    free_count_2m: usize,
    /// Pages in this node's 1G pool.
    pages_1g: [HugePage; MAX_PAGES_PER_NODE_1G],
    /// Number of allocated pages in the 1G pool.
    count_1g: usize,
    /// Head of the 1G free list.
    free_head_1g: u32,
    /// Number of free 1G pages.
    free_count_1g: usize,
    /// Total bytes reserved on this node.
    reserved_bytes: u64,
}

impl NodeReserve {
    /// Creates a new empty node reserve.
    pub const fn new(node_id: u8) -> Self {
        Self {
            node_id,
            pages_2m: [const { HugePage::new(0, HugePageOrder::Order2M, 0) };
                MAX_PAGES_PER_NODE_2M],
            count_2m: 0,
            free_head_2m: FREE_LIST_END,
            free_count_2m: 0,
            pages_1g: [const { HugePage::new(0, HugePageOrder::Order1G, 0) };
                MAX_PAGES_PER_NODE_1G],
            count_1g: 0,
            free_head_1g: FREE_LIST_END,
            free_count_1g: 0,
            reserved_bytes: 0,
        }
    }

    /// Returns the node ID.
    pub const fn node_id(&self) -> u8 {
        self.node_id
    }

    /// Returns the number of free 2M pages on this node.
    pub const fn free_2m(&self) -> usize {
        self.free_count_2m
    }

    /// Returns the number of free 1G pages on this node.
    pub const fn free_1g(&self) -> usize {
        self.free_count_1g
    }

    /// Adds a 2M page to this node's reserve pool.
    pub fn add_page_2m(&mut self, pfn: u64) -> Result<()> {
        if self.count_2m >= MAX_PAGES_PER_NODE_2M {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count_2m;
        self.pages_2m[idx] = HugePage::new(pfn, HugePageOrder::Order2M, self.node_id);
        self.pages_2m[idx].next_free = self.free_head_2m;
        self.free_head_2m = idx as u32;
        self.count_2m += 1;
        self.free_count_2m += 1;
        self.reserved_bytes += HUGE_2M;
        Ok(())
    }

    /// Adds a 1G page to this node's reserve pool.
    pub fn add_page_1g(&mut self, pfn: u64) -> Result<()> {
        if self.count_1g >= MAX_PAGES_PER_NODE_1G {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count_1g;
        self.pages_1g[idx] = HugePage::new(pfn, HugePageOrder::Order1G, self.node_id);
        self.pages_1g[idx].next_free = self.free_head_1g;
        self.free_head_1g = idx as u32;
        self.count_1g += 1;
        self.free_count_1g += 1;
        self.reserved_bytes += HUGE_1G;
        Ok(())
    }

    /// Allocates a 2M huge page from this node. Returns the page index.
    pub fn alloc_2m(&mut self) -> Result<usize> {
        if self.free_head_2m == FREE_LIST_END {
            return Err(Error::OutOfMemory);
        }
        let idx = self.free_head_2m as usize;
        self.free_head_2m = self.pages_2m[idx].next_free;
        self.pages_2m[idx].next_free = FREE_LIST_END;
        self.pages_2m[idx].state = HugePageState::Allocated;
        self.pages_2m[idx].generation += 1;
        self.free_count_2m -= 1;
        Ok(idx)
    }

    /// Frees a 2M huge page back to this node's pool.
    pub fn release_2m(&mut self, idx: usize) -> Result<()> {
        if idx >= self.count_2m {
            return Err(Error::InvalidArgument);
        }
        if self.pages_2m[idx].state != HugePageState::Allocated {
            return Err(Error::InvalidArgument);
        }
        self.pages_2m[idx].state = HugePageState::Free;
        self.pages_2m[idx].refcount = 0;
        self.pages_2m[idx].next_free = self.free_head_2m;
        self.pages_2m[idx].generation += 1;
        self.free_head_2m = idx as u32;
        self.free_count_2m += 1;
        Ok(())
    }

    /// Allocates a 1G huge page from this node. Returns the page index.
    pub fn alloc_1g(&mut self) -> Result<usize> {
        if self.free_head_1g == FREE_LIST_END {
            return Err(Error::OutOfMemory);
        }
        let idx = self.free_head_1g as usize;
        self.free_head_1g = self.pages_1g[idx].next_free;
        self.pages_1g[idx].next_free = FREE_LIST_END;
        self.pages_1g[idx].state = HugePageState::Allocated;
        self.pages_1g[idx].generation += 1;
        self.free_count_1g -= 1;
        Ok(idx)
    }

    /// Frees a 1G huge page back to this node's pool.
    pub fn release_1g(&mut self, idx: usize) -> Result<()> {
        if idx >= self.count_1g {
            return Err(Error::InvalidArgument);
        }
        if self.pages_1g[idx].state != HugePageState::Allocated {
            return Err(Error::InvalidArgument);
        }
        self.pages_1g[idx].state = HugePageState::Free;
        self.pages_1g[idx].refcount = 0;
        self.pages_1g[idx].next_free = self.free_head_1g;
        self.pages_1g[idx].generation += 1;
        self.free_head_1g = idx as u32;
        self.free_count_1g += 1;
        Ok(())
    }

    /// Returns the total reserved bytes on this node.
    pub const fn reserved_bytes(&self) -> u64 {
        self.reserved_bytes
    }
}

// -------------------------------------------------------------------
// HugetlbMeminfo
// -------------------------------------------------------------------

/// Represents `/proc/meminfo` hugetlb-related fields.
#[derive(Debug, Clone, Copy, Default)]
pub struct HugetlbMeminfo {
    /// Total number of 2M huge pages.
    pub huge_pages_total_2m: u64,
    /// Free 2M huge pages.
    pub huge_pages_free_2m: u64,
    /// Reserved (committed but not allocated) 2M pages.
    pub huge_pages_rsvd_2m: u64,
    /// Surplus 2M pages (over-committed).
    pub huge_pages_surp_2m: u64,
    /// Size of 2M huge pages in KiB.
    pub hugepagesize_2m_kb: u64,
    /// Total number of 1G huge pages.
    pub huge_pages_total_1g: u64,
    /// Free 1G huge pages.
    pub huge_pages_free_1g: u64,
    /// Total hugetlb memory in KiB.
    pub hugetlb_kb: u64,
}

impl HugetlbMeminfo {
    /// Creates a new zeroed meminfo.
    pub const fn new() -> Self {
        Self {
            huge_pages_total_2m: 0,
            huge_pages_free_2m: 0,
            huge_pages_rsvd_2m: 0,
            huge_pages_surp_2m: 0,
            hugepagesize_2m_kb: HUGE_2M / 1024,
            huge_pages_total_1g: 0,
            huge_pages_free_1g: 0,
            hugetlb_kb: 0,
        }
    }
}

// -------------------------------------------------------------------
// HugetlbStats
// -------------------------------------------------------------------

/// Allocation statistics for the hugetlb pool.
#[derive(Debug, Clone, Copy, Default)]
pub struct HugetlbStats {
    /// Total 2M allocations (successful).
    pub allocs_2m: u64,
    /// Total 2M frees.
    pub frees_2m: u64,
    /// Total 1G allocations (successful).
    pub allocs_1g: u64,
    /// Total 1G frees.
    pub frees_1g: u64,
    /// Total allocation failures.
    pub alloc_failures: u64,
    /// Cross-node fallback allocations.
    pub fallback_allocs: u64,
}

impl HugetlbStats {
    /// Creates new zeroed statistics.
    pub const fn new() -> Self {
        Self {
            allocs_2m: 0,
            frees_2m: 0,
            allocs_1g: 0,
            frees_1g: 0,
            alloc_failures: 0,
            fallback_allocs: 0,
        }
    }
}

// -------------------------------------------------------------------
// HugetlbPool
// -------------------------------------------------------------------

/// Global hugetlb pool managing per-node huge page reserves.
///
/// Allocation is NUMA-aware: first try the preferred node, then
/// fall back to other nodes in distance order.
#[derive(Debug)]
pub struct HugetlbPool {
    /// Per-node reserves.
    nodes: [NodeReserve; MAX_NUMA_NODES],
    /// Number of active NUMA nodes.
    nr_nodes: usize,
    /// Allocation statistics.
    stats: HugetlbStats,
    /// Maximum surplus pages allowed (over-commit limit).
    max_surplus: usize,
    /// Current surplus count.
    surplus_count: usize,
    /// Whether the pool is initialized.
    initialized: bool,
}

impl HugetlbPool {
    /// Creates a new uninitialized pool.
    pub const fn new() -> Self {
        Self {
            nodes: [const { NodeReserve::new(0) }; MAX_NUMA_NODES],
            nr_nodes: 0,
            stats: HugetlbStats::new(),
            max_surplus: 0,
            surplus_count: 0,
            initialized: false,
        }
    }

    /// Initializes the pool with the given number of NUMA nodes.
    pub fn init(&mut self, nr_nodes: usize) -> Result<()> {
        if nr_nodes == 0 || nr_nodes > MAX_NUMA_NODES {
            return Err(Error::InvalidArgument);
        }
        let mut i = 0;
        while i < nr_nodes {
            self.nodes[i] = NodeReserve::new(i as u8);
            i += 1;
        }
        self.nr_nodes = nr_nodes;
        self.initialized = true;
        Ok(())
    }

    /// Sets the maximum surplus (over-commit) limit.
    pub fn set_max_surplus(&mut self, max: usize) {
        self.max_surplus = max;
    }

    /// Adds a 2M huge page to the specified node's reserve.
    pub fn reserve_2m(&mut self, node_id: usize, pfn: u64) -> Result<()> {
        self.check_initialized()?;
        if node_id >= self.nr_nodes {
            return Err(Error::InvalidArgument);
        }
        self.nodes[node_id].add_page_2m(pfn)
    }

    /// Adds a 1G huge page to the specified node's reserve.
    pub fn reserve_1g(&mut self, node_id: usize, pfn: u64) -> Result<()> {
        self.check_initialized()?;
        if node_id >= self.nr_nodes {
            return Err(Error::InvalidArgument);
        }
        self.nodes[node_id].add_page_1g(pfn)
    }

    /// Allocates a huge page, preferring the given NUMA node.
    ///
    /// Falls back to other nodes if the preferred node is exhausted.
    pub fn alloc_huge_page(
        &mut self,
        order: HugePageOrder,
        preferred_node: usize,
    ) -> Result<AllocResult> {
        self.check_initialized()?;

        // Try preferred node first
        if preferred_node < self.nr_nodes {
            if let Ok(idx) = self.try_alloc_on_node(preferred_node, order) {
                self.record_alloc(order);
                return Ok(AllocResult {
                    node_id: preferred_node as u8,
                    page_index: idx,
                    fallback: false,
                });
            }
        }

        // Fallback: try other nodes
        for nid in 0..self.nr_nodes {
            if nid == preferred_node {
                continue;
            }
            if let Ok(idx) = self.try_alloc_on_node(nid, order) {
                self.stats.fallback_allocs += 1;
                self.record_alloc(order);
                return Ok(AllocResult {
                    node_id: nid as u8,
                    page_index: idx,
                    fallback: true,
                });
            }
        }

        self.stats.alloc_failures += 1;
        Err(Error::OutOfMemory)
    }

    /// Frees a huge page back to its node's pool.
    pub fn free_huge_page(
        &mut self,
        order: HugePageOrder,
        node_id: usize,
        page_index: usize,
    ) -> Result<()> {
        self.check_initialized()?;
        if node_id >= self.nr_nodes {
            return Err(Error::InvalidArgument);
        }
        match order {
            HugePageOrder::Order2M => {
                self.nodes[node_id].release_2m(page_index)?;
                self.stats.frees_2m += 1;
            }
            HugePageOrder::Order1G => {
                self.nodes[node_id].release_1g(page_index)?;
                self.stats.frees_1g += 1;
            }
        }
        Ok(())
    }

    /// Returns the current meminfo snapshot.
    pub fn meminfo(&self) -> HugetlbMeminfo {
        let mut info = HugetlbMeminfo::new();
        for nid in 0..self.nr_nodes {
            let node = &self.nodes[nid];
            info.huge_pages_total_2m += node.count_2m as u64;
            info.huge_pages_free_2m += node.free_count_2m as u64;
            info.huge_pages_total_1g += node.count_1g as u64;
            info.huge_pages_free_1g += node.free_count_1g as u64;
        }
        info.huge_pages_surp_2m = self.surplus_count as u64;
        // Total hugetlb memory in KiB
        info.hugetlb_kb = info.huge_pages_total_2m * (HUGE_2M / 1024)
            + info.huge_pages_total_1g * (HUGE_1G / 1024);
        info
    }

    /// Returns a reference to the allocation statistics.
    pub const fn stats(&self) -> &HugetlbStats {
        &self.stats
    }

    /// Returns the number of active NUMA nodes.
    pub const fn nr_nodes(&self) -> usize {
        self.nr_nodes
    }

    /// Returns the total number of free 2M pages across all nodes.
    pub fn total_free_2m(&self) -> usize {
        let mut total = 0;
        for nid in 0..self.nr_nodes {
            total += self.nodes[nid].free_count_2m;
        }
        total
    }

    /// Returns the total number of free 1G pages across all nodes.
    pub fn total_free_1g(&self) -> usize {
        let mut total = 0;
        for nid in 0..self.nr_nodes {
            total += self.nodes[nid].free_count_1g;
        }
        total
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    /// Ensures the pool is initialized.
    fn check_initialized(&self) -> Result<()> {
        if !self.initialized {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    /// Tries to allocate a huge page on the given node.
    fn try_alloc_on_node(&mut self, node_id: usize, order: HugePageOrder) -> Result<usize> {
        match order {
            HugePageOrder::Order2M => self.nodes[node_id].alloc_2m(),
            HugePageOrder::Order1G => self.nodes[node_id].alloc_1g(),
        }
    }

    /// Records an allocation in statistics.
    fn record_alloc(&mut self, order: HugePageOrder) {
        match order {
            HugePageOrder::Order2M => self.stats.allocs_2m += 1,
            HugePageOrder::Order1G => self.stats.allocs_1g += 1,
        }
    }
}

impl Default for HugetlbPool {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// AllocResult
// -------------------------------------------------------------------

/// Result of a successful huge page allocation.
#[derive(Debug, Clone, Copy)]
pub struct AllocResult {
    /// NUMA node the page was allocated from.
    pub node_id: u8,
    /// Index of the page within the node's pool.
    pub page_index: usize,
    /// Whether this was a fallback (non-preferred node) allocation.
    pub fallback: bool,
}
