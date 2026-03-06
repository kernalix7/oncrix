// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Zero page allocation and shared mapping.
//!
//! Anonymous pages that have never been written contain only zeroes.
//! Instead of allocating a unique physical frame for each such page,
//! the kernel maps them all to a single shared read-only zero page
//! (`ZERO_PAGE`). On the first write, a copy-on-write fault allocates
//! a real frame and copies the zeroes (or simply zeroes the new page).
//!
//! On NUMA systems each node may have its own zero page to avoid
//! cross-node memory traffic on page-table walks.
//!
//! # Key Types
//!
//! - [`ZeroPageState`] — lifecycle of a per-node zero page
//! - [`NodeZeroPage`] — per-NUMA-node zero page descriptor
//! - [`ZeroPageRef`] — a reference-counted handle to a zero page
//! - [`ZeroPageManager`] — global zero page management
//! - [`ZeroPageStats`] — usage statistics
//!
//! Reference: Linux `mm/memory.c` (`ZERO_PAGE()`),
//! `arch/x86/mm/init.c`, `include/linux/mm.h` (`is_zero_pfn`).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum NUMA nodes supported.
const MAX_NUMA_NODES: usize = 8;

/// PFN value indicating the global (non-NUMA) zero page.
const GLOBAL_ZERO_PFN: u64 = 0;

/// Maximum number of concurrent zero-page references tracked.
const MAX_ZERO_REFS: usize = 4096;

/// Huge zero page PFN sentinel (2 MiB).
const HUGE_ZERO_PFN: u64 = 1;

/// 2 MiB huge page size.
const HUGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;

// -------------------------------------------------------------------
// ZeroPageState
// -------------------------------------------------------------------

/// Lifecycle state of a zero page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ZeroPageState {
    /// Zero page has not been allocated yet.
    #[default]
    Unallocated,
    /// Zero page is allocated and available for mapping.
    Active,
    /// Zero page is being freed (hot-remove or shutdown).
    Freeing,
}

// -------------------------------------------------------------------
// NodeZeroPage
// -------------------------------------------------------------------

/// Per-NUMA-node zero page descriptor.
#[derive(Debug, Clone, Copy)]
pub struct NodeZeroPage {
    /// NUMA node identifier.
    pub node_id: u8,
    /// Physical frame number backing this zero page.
    pub pfn: u64,
    /// Physical address of the zero page.
    pub phys_addr: u64,
    /// Current state.
    pub state: ZeroPageState,
    /// Reference count (number of PTEs pointing here).
    pub refcount: u64,
    /// Total times this zero page has been mapped.
    pub map_count: u64,
    /// Total times a CoW fault broke away from this zero page.
    pub cow_breaks: u64,
}

impl Default for NodeZeroPage {
    fn default() -> Self {
        Self {
            node_id: 0,
            pfn: 0,
            phys_addr: 0,
            state: ZeroPageState::Unallocated,
            refcount: 0,
            map_count: 0,
            cow_breaks: 0,
        }
    }
}

impl NodeZeroPage {
    /// Returns true if this zero page is active and usable.
    pub fn is_active(&self) -> bool {
        self.state == ZeroPageState::Active
    }

    /// Increments the reference count and map counter.
    pub fn acquire(&mut self) {
        self.refcount = self.refcount.saturating_add(1);
        self.map_count = self.map_count.saturating_add(1);
    }

    /// Decrements the reference count.
    pub fn release(&mut self) {
        self.refcount = self.refcount.saturating_sub(1);
    }

    /// Records a CoW break from this zero page.
    pub fn record_cow_break(&mut self) {
        self.cow_breaks = self.cow_breaks.saturating_add(1);
        self.release();
    }
}

// -------------------------------------------------------------------
// ZeroPageRef
// -------------------------------------------------------------------

/// A reference-counted handle to a zero page mapping.
///
/// When a PTE is set to point at the zero page, a `ZeroPageRef` is
/// logically held. Dropping or releasing the ref decrements the
/// zero page's reference count.
#[derive(Debug, Clone, Copy)]
pub struct ZeroPageRef {
    /// Virtual address mapped to the zero page.
    pub vaddr: u64,
    /// Node whose zero page is referenced.
    pub node_id: u8,
    /// Whether this is a huge (2 MiB) zero page reference.
    pub huge: bool,
}

impl Default for ZeroPageRef {
    fn default() -> Self {
        Self {
            vaddr: 0,
            node_id: 0,
            huge: false,
        }
    }
}

// -------------------------------------------------------------------
// ZeroPageStats
// -------------------------------------------------------------------

/// Global zero page usage statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct ZeroPageStats {
    /// Total zero page mappings created.
    pub total_mappings: u64,
    /// Total zero page references currently active.
    pub active_refs: u64,
    /// Total CoW breaks from zero pages.
    pub total_cow_breaks: u64,
    /// Total huge zero page mappings.
    pub huge_mappings: u64,
    /// Total huge zero page CoW breaks.
    pub huge_cow_breaks: u64,
    /// Total is_zero_pfn checks performed.
    pub zero_pfn_checks: u64,
    /// Total is_zero_pfn checks that returned true.
    pub zero_pfn_hits: u64,
    /// Memory saved in bytes (active_refs * PAGE_SIZE).
    pub memory_saved_bytes: u64,
}

// -------------------------------------------------------------------
// ZeroPageManager
// -------------------------------------------------------------------

/// Global manager for zero page allocation and mapping.
///
/// Maintains per-node zero pages, tracks references, and provides
/// the `is_zero_pfn` fast-path check.
pub struct ZeroPageManager {
    /// Per-node zero page descriptors.
    nodes: [NodeZeroPage; MAX_NUMA_NODES],
    /// Number of NUMA nodes with active zero pages.
    nr_active_nodes: usize,
    /// Global (fallback) zero page PFN.
    global_zero_pfn: u64,
    /// Huge (2 MiB) zero page PFN.
    huge_zero_pfn: u64,
    /// Whether the huge zero page is allocated.
    huge_zero_active: bool,
    /// Reference count for the huge zero page.
    huge_zero_refcount: u64,
    /// Active zero-page references.
    refs: [ZeroPageRef; MAX_ZERO_REFS],
    /// Number of active references.
    nr_refs: usize,
    /// Cumulative statistics.
    stats: ZeroPageStats,
}

impl ZeroPageManager {
    /// Creates a new zero page manager.
    ///
    /// `global_pfn` is the PFN of the global zero page frame.
    pub fn new(global_pfn: u64) -> Self {
        Self {
            nodes: [const {
                NodeZeroPage {
                    node_id: 0,
                    pfn: 0,
                    phys_addr: 0,
                    state: ZeroPageState::Unallocated,
                    refcount: 0,
                    map_count: 0,
                    cow_breaks: 0,
                }
            }; MAX_NUMA_NODES],
            nr_active_nodes: 0,
            global_zero_pfn: global_pfn,
            huge_zero_pfn: 0,
            huge_zero_active: false,
            huge_zero_refcount: 0,
            refs: [const {
                ZeroPageRef {
                    vaddr: 0,
                    node_id: 0,
                    huge: false,
                }
            }; MAX_ZERO_REFS],
            nr_refs: 0,
            stats: ZeroPageStats::default(),
        }
    }

    /// Returns current statistics.
    pub fn stats(&self) -> &ZeroPageStats {
        &self.stats
    }

    /// Returns the global zero page PFN.
    pub fn global_zero_pfn(&self) -> u64 {
        self.global_zero_pfn
    }

    /// Initializes a per-node zero page.
    ///
    /// `node_id` is the NUMA node, `pfn` is the pre-zeroed frame.
    pub fn init_node_zero_page(&mut self, node_id: u8, pfn: u64) -> Result<()> {
        let nid = node_id as usize;
        if nid >= MAX_NUMA_NODES {
            return Err(Error::InvalidArgument);
        }
        self.nodes[nid] = NodeZeroPage {
            node_id,
            pfn,
            phys_addr: pfn * PAGE_SIZE,
            state: ZeroPageState::Active,
            refcount: 0,
            map_count: 0,
            cow_breaks: 0,
        };
        self.nr_active_nodes += 1;
        Ok(())
    }

    /// Initializes the huge (2 MiB) zero page.
    pub fn init_huge_zero_page(&mut self, pfn: u64) -> Result<()> {
        if self.huge_zero_active {
            return Err(Error::AlreadyExists);
        }
        self.huge_zero_pfn = pfn;
        self.huge_zero_active = true;
        self.huge_zero_refcount = 0;
        Ok(())
    }

    /// Returns the zero page PFN for a given NUMA node.
    ///
    /// Falls back to the global zero page if the node has no
    /// dedicated zero page.
    pub fn zero_pfn_for_node(&self, node_id: u8) -> u64 {
        let nid = node_id as usize;
        if nid < MAX_NUMA_NODES && self.nodes[nid].is_active() {
            return self.nodes[nid].pfn;
        }
        self.global_zero_pfn
    }

    /// Checks whether a PFN is any zero page (global or per-node).
    pub fn is_zero_pfn(&mut self, pfn: u64) -> bool {
        self.stats.zero_pfn_checks += 1;
        if pfn == self.global_zero_pfn {
            self.stats.zero_pfn_hits += 1;
            return true;
        }
        if self.huge_zero_active && pfn == self.huge_zero_pfn {
            self.stats.zero_pfn_hits += 1;
            return true;
        }
        for i in 0..MAX_NUMA_NODES {
            if self.nodes[i].is_active() && self.nodes[i].pfn == pfn {
                self.stats.zero_pfn_hits += 1;
                return true;
            }
        }
        false
    }

    /// Maps a virtual address to the zero page for a given node.
    ///
    /// Returns the PFN of the zero page that was mapped.
    pub fn map_zero_page(&mut self, vaddr: u64, node_id: u8) -> Result<u64> {
        if self.nr_refs >= MAX_ZERO_REFS {
            return Err(Error::OutOfMemory);
        }
        let pfn = self.zero_pfn_for_node(node_id);
        let nid = node_id as usize;
        if nid < MAX_NUMA_NODES && self.nodes[nid].is_active() {
            self.nodes[nid].acquire();
        }
        self.refs[self.nr_refs] = ZeroPageRef {
            vaddr,
            node_id,
            huge: false,
        };
        self.nr_refs += 1;
        self.stats.total_mappings += 1;
        self.stats.active_refs += 1;
        self.update_memory_saved();
        Ok(pfn)
    }

    /// Maps a virtual address to the huge zero page.
    pub fn map_huge_zero_page(&mut self, vaddr: u64) -> Result<u64> {
        if !self.huge_zero_active {
            return Err(Error::NotFound);
        }
        if self.nr_refs >= MAX_ZERO_REFS {
            return Err(Error::OutOfMemory);
        }
        self.huge_zero_refcount = self.huge_zero_refcount.saturating_add(1);
        self.refs[self.nr_refs] = ZeroPageRef {
            vaddr,
            node_id: 0,
            huge: true,
        };
        self.nr_refs += 1;
        self.stats.huge_mappings += 1;
        self.stats.active_refs += 1;
        self.update_memory_saved();
        Ok(self.huge_zero_pfn)
    }

    /// Handles a CoW break from a zero page at `vaddr`.
    ///
    /// Finds the reference, decrements the zero page refcount,
    /// and removes the tracking entry.
    pub fn cow_break(&mut self, vaddr: u64) -> Result<()> {
        let pos = (0..self.nr_refs).position(|i| self.refs[i].vaddr == vaddr);
        let idx = pos.ok_or(Error::NotFound)?;
        let zref = self.refs[idx];

        if zref.huge {
            self.huge_zero_refcount = self.huge_zero_refcount.saturating_sub(1);
            self.stats.huge_cow_breaks += 1;
        } else {
            let nid = zref.node_id as usize;
            if nid < MAX_NUMA_NODES && self.nodes[nid].is_active() {
                self.nodes[nid].record_cow_break();
            }
        }

        // Remove entry by swapping with last.
        self.nr_refs -= 1;
        if idx < self.nr_refs {
            self.refs[idx] = self.refs[self.nr_refs];
        }

        self.stats.total_cow_breaks += 1;
        self.stats.active_refs = self.stats.active_refs.saturating_sub(1);
        self.update_memory_saved();
        Ok(())
    }

    /// Updates the memory-saved statistic.
    fn update_memory_saved(&mut self) {
        let mut saved = 0u64;
        for i in 0..self.nr_refs {
            if self.refs[i].huge {
                saved += HUGE_PAGE_SIZE;
            } else {
                saved += PAGE_SIZE;
            }
        }
        self.stats.memory_saved_bytes = saved;
    }

    /// Returns the number of active zero page references.
    pub fn active_ref_count(&self) -> usize {
        self.nr_refs
    }

    /// Returns the huge zero page reference count.
    pub fn huge_zero_refcount(&self) -> u64 {
        self.huge_zero_refcount
    }

    /// Returns the number of NUMA nodes with active zero pages.
    pub fn active_node_count(&self) -> usize {
        self.nr_active_nodes
    }

    /// Returns per-node zero page information.
    pub fn node_info(&self, node_id: u8) -> Result<&NodeZeroPage> {
        let nid = node_id as usize;
        if nid >= MAX_NUMA_NODES {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.nodes[nid])
    }
}
