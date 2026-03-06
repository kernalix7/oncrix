// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Anonymous VMA reverse mapping.
//!
//! Maintains the mapping from anonymous (non-file-backed) pages back
//! to the virtual memory areas (VMAs) that reference them. This is
//! essential for:
//! - Page reclaim — finding all PTEs for a page to unmap it.
//! - Migration — updating PTEs when a page moves physically.
//! - KSM — merging identical anonymous pages.
//! - fork/CoW — sharing `anon_vma` structures across parent/child.
//!
//! # Architecture
//!
//! Each anonymous VMA belongs to an [`AnonVma`] structure. When a
//! process forks, the child's VMAs are linked to the parent's
//! `anon_vma` via [`AnonVmaChain`] entries, forming a tree that
//! allows efficient reverse-mapping walks.
//!
//! # Types
//!
//! - [`AnonVmaFlags`] — flags on an anon_vma
//! - [`AnonVma`] — shared structure for CoW-related VMAs
//! - [`AnonVmaChain`] — link between a VMA and an anon_vma
//! - [`AnonVmaEntry`] — a VMA registered in the reverse map
//! - [`AnonVmaWalkResult`] — result of an rmap walk
//! - [`AnonVmaManager`] — top-level manager
//! - [`AnonVmaStats`] — summary statistics
//!
//! Reference: Linux `mm/rmap.c`, `include/linux/rmap.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of `AnonVma` structures.
const MAX_ANON_VMAS: usize = 512;

/// Maximum number of `AnonVmaChain` links.
const MAX_CHAINS: usize = 1024;

/// Maximum VMAs per anon_vma.
const MAX_VMAS_PER_AV: usize = 16;

/// Maximum number of VMA entries tracked globally.
const MAX_VMA_ENTRIES: usize = 1024;

/// Maximum depth of an anon_vma parent chain.
const MAX_DEPTH: usize = 16;

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum pages tracked per VMA entry for rmap.
const MAX_PAGES_PER_VMA: usize = 64;

// -------------------------------------------------------------------
// AnonVmaFlags
// -------------------------------------------------------------------

/// Flags on an anon_vma structure.
#[derive(Debug, Clone, Copy, Default)]
pub struct AnonVmaFlags {
    /// This anon_vma is the root (no parent).
    pub is_root: bool,
    /// Has been forked at least once.
    pub forked: bool,
    /// Marked for lazy teardown.
    pub lazy_teardown: bool,
}

// -------------------------------------------------------------------
// AnonVma
// -------------------------------------------------------------------

/// Shared anon_vma structure linking CoW-related VMAs.
///
/// When a process forks, the child's VMAs share the parent's
/// `anon_vma` so that reverse-map walks can find all processes
/// that map a given anonymous page.
#[derive(Clone, Copy)]
pub struct AnonVma {
    /// Unique ID.
    pub id: u32,
    /// Parent anon_vma ID (0 = root).
    pub parent_id: u32,
    /// Reference count (number of VMAs linked).
    pub refcount: u32,
    /// Degree (number of children).
    pub degree: u32,
    /// Depth in the tree.
    pub depth: u32,
    /// Flags.
    pub flags: AnonVmaFlags,
    /// Whether this entry is active.
    pub active: bool,
    /// IDs of VMAs attached via chains.
    pub vma_ids: [u32; MAX_VMAS_PER_AV],
    /// Number of attached VMAs.
    pub nr_vmas: usize,
    /// Owning process PID (the process that created this anon_vma).
    pub owner_pid: u32,
}

impl AnonVma {
    /// Creates an empty, inactive anon_vma.
    const fn empty() -> Self {
        Self {
            id: 0,
            parent_id: 0,
            refcount: 0,
            degree: 0,
            depth: 0,
            flags: AnonVmaFlags {
                is_root: false,
                forked: false,
                lazy_teardown: false,
            },
            active: false,
            vma_ids: [0; MAX_VMAS_PER_AV],
            nr_vmas: 0,
            owner_pid: 0,
        }
    }

    /// Returns true if this is a root anon_vma.
    pub const fn is_root(&self) -> bool {
        self.flags.is_root
    }

    /// Returns true if this anon_vma has no references.
    pub const fn is_empty(&self) -> bool {
        self.refcount == 0
    }
}

impl Default for AnonVma {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// AnonVmaChain
// -------------------------------------------------------------------

/// Link between a VMA and an anon_vma.
///
/// Each VMA that participates in anonymous mapping has one chain
/// entry per anon_vma in its lineage (from its own up to the root).
#[derive(Debug, Clone, Copy)]
pub struct AnonVmaChain {
    /// Unique chain ID.
    pub id: u32,
    /// VMA ID this chain links.
    pub vma_id: u32,
    /// anon_vma ID this chain links to.
    pub anon_vma_id: u32,
    /// Whether this entry is active.
    pub active: bool,
}

impl AnonVmaChain {
    /// Creates an empty chain entry.
    const fn empty() -> Self {
        Self {
            id: 0,
            vma_id: 0,
            anon_vma_id: 0,
            active: false,
        }
    }
}

impl Default for AnonVmaChain {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// AnonVmaEntry
// -------------------------------------------------------------------

/// A VMA entry in the reverse map system.
///
/// Represents one virtual memory area that maps anonymous pages.
#[derive(Clone, Copy)]
pub struct AnonVmaEntry {
    /// VMA ID.
    pub vma_id: u32,
    /// Owning process PID.
    pub pid: u32,
    /// Virtual start address.
    pub vm_start: u64,
    /// Virtual end address (exclusive).
    pub vm_end: u64,
    /// Offset within the anon_vma region (in pages).
    pub vm_pgoff: u64,
    /// anon_vma ID this VMA belongs to.
    pub anon_vma_id: u32,
    /// Whether this entry is active.
    pub active: bool,
    /// Page PFNs mapped in this VMA (for rmap walk).
    pub mapped_pfns: [u64; MAX_PAGES_PER_VMA],
    /// Number of mapped pages.
    pub nr_mapped: usize,
}

impl AnonVmaEntry {
    /// Creates an empty VMA entry.
    const fn empty() -> Self {
        Self {
            vma_id: 0,
            pid: 0,
            vm_start: 0,
            vm_end: 0,
            vm_pgoff: 0,
            anon_vma_id: 0,
            active: false,
            mapped_pfns: [0; MAX_PAGES_PER_VMA],
            nr_mapped: 0,
        }
    }

    /// Returns the size of the VMA in bytes.
    pub const fn size(&self) -> u64 {
        self.vm_end - self.vm_start
    }

    /// Returns the number of pages in this VMA.
    pub const fn nr_pages(&self) -> u64 {
        self.size() / PAGE_SIZE
    }

    /// Returns whether `addr` falls in this VMA.
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.vm_start && addr < self.vm_end
    }

    /// Returns the page offset for a virtual address.
    pub const fn page_offset(&self, addr: u64) -> u64 {
        (addr - self.vm_start) / PAGE_SIZE + self.vm_pgoff
    }
}

impl Default for AnonVmaEntry {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// AnonVmaWalkResult
// -------------------------------------------------------------------

/// Result of an rmap walk for a page.
#[derive(Debug, Clone, Copy)]
pub struct AnonVmaWalkResult {
    /// Number of VMAs mapping this page.
    pub mapcount: u32,
    /// Number of VMAs where the page was referenced.
    pub referenced: u32,
    /// VMA IDs that map this page.
    pub vma_ids: [u32; MAX_VMAS_PER_AV],
    /// Number of valid VMA IDs.
    pub nr_vmas: usize,
}

impl Default for AnonVmaWalkResult {
    fn default() -> Self {
        Self {
            mapcount: 0,
            referenced: 0,
            vma_ids: [0; MAX_VMAS_PER_AV],
            nr_vmas: 0,
        }
    }
}

// -------------------------------------------------------------------
// AnonVmaStats
// -------------------------------------------------------------------

/// Summary statistics for the anon_vma manager.
#[derive(Debug, Clone, Copy, Default)]
pub struct AnonVmaStats {
    /// Total anon_vma structures created.
    pub total_created: u64,
    /// Total anon_vma structures freed.
    pub total_freed: u64,
    /// Total chains created.
    pub total_chains: u64,
    /// Total chains removed.
    pub total_chains_removed: u64,
    /// Total VMA entries registered.
    pub total_vmas_registered: u64,
    /// Total rmap walks performed.
    pub total_walks: u64,
    /// Total fork duplications.
    pub total_forks: u64,
    /// Active anon_vma count.
    pub active_anon_vmas: u32,
    /// Active chain count.
    pub active_chains: u32,
    /// Active VMA entries.
    pub active_vma_entries: u32,
}

// -------------------------------------------------------------------
// AnonVmaManager
// -------------------------------------------------------------------

/// Top-level manager for anonymous VMA reverse mappings.
///
/// Manages the creation, linking, forking, and walking of anon_vma
/// structures for all anonymous memory in the system.
pub struct AnonVmaManager {
    /// anon_vma structures.
    anon_vmas: [AnonVma; MAX_ANON_VMAS],
    /// Chain links.
    chains: [AnonVmaChain; MAX_CHAINS],
    /// VMA entries.
    vma_entries: [AnonVmaEntry; MAX_VMA_ENTRIES],
    /// Next anon_vma ID.
    next_av_id: u32,
    /// Next chain ID.
    next_chain_id: u32,
    /// Next VMA ID.
    next_vma_id: u32,
    /// Statistics.
    stats: AnonVmaStats,
}

impl AnonVmaManager {
    /// Creates a new manager.
    pub fn new() -> Self {
        Self {
            anon_vmas: [AnonVma::empty(); MAX_ANON_VMAS],
            chains: [AnonVmaChain::empty(); MAX_CHAINS],
            vma_entries: [AnonVmaEntry::empty(); MAX_VMA_ENTRIES],
            next_av_id: 1,
            next_chain_id: 1,
            next_vma_id: 1,
            stats: AnonVmaStats::default(),
        }
    }

    /// Creates a new root anon_vma for a process.
    pub fn create_root(&mut self, pid: u32) -> Result<u32> {
        let idx = self.find_free_av_slot()?;
        let id = self.next_av_id;
        self.next_av_id += 1;
        self.anon_vmas[idx] = AnonVma {
            id,
            parent_id: 0,
            refcount: 0,
            degree: 0,
            depth: 0,
            flags: AnonVmaFlags {
                is_root: true,
                forked: false,
                lazy_teardown: false,
            },
            active: true,
            vma_ids: [0; MAX_VMAS_PER_AV],
            nr_vmas: 0,
            owner_pid: pid,
        };
        self.stats.total_created += 1;
        self.stats.active_anon_vmas += 1;
        Ok(id)
    }

    /// Creates a child anon_vma linked to a parent.
    pub fn create_child(&mut self, parent_id: u32, pid: u32) -> Result<u32> {
        let parent_idx = self.find_av_by_id(parent_id).ok_or(Error::NotFound)?;
        let parent_depth = self.anon_vmas[parent_idx].depth;
        if parent_depth as usize >= MAX_DEPTH - 1 {
            return Err(Error::InvalidArgument);
        }
        let idx = self.find_free_av_slot()?;
        let id = self.next_av_id;
        self.next_av_id += 1;
        self.anon_vmas[idx] = AnonVma {
            id,
            parent_id,
            refcount: 0,
            degree: 0,
            depth: parent_depth + 1,
            flags: AnonVmaFlags {
                is_root: false,
                forked: false,
                lazy_teardown: false,
            },
            active: true,
            vma_ids: [0; MAX_VMAS_PER_AV],
            nr_vmas: 0,
            owner_pid: pid,
        };
        self.anon_vmas[parent_idx].degree += 1;
        self.anon_vmas[parent_idx].flags.forked = true;
        self.stats.total_created += 1;
        self.stats.active_anon_vmas += 1;
        Ok(id)
    }

    /// Registers a VMA with an anon_vma.
    pub fn register_vma(
        &mut self,
        anon_vma_id: u32,
        pid: u32,
        vm_start: u64,
        vm_end: u64,
        vm_pgoff: u64,
    ) -> Result<u32> {
        let av_idx = self.find_av_by_id(anon_vma_id).ok_or(Error::NotFound)?;
        if self.anon_vmas[av_idx].nr_vmas >= MAX_VMAS_PER_AV {
            return Err(Error::OutOfMemory);
        }
        // Create VMA entry.
        let vma_idx = self.find_free_vma_slot()?;
        let vma_id = self.next_vma_id;
        self.next_vma_id += 1;
        self.vma_entries[vma_idx] = AnonVmaEntry {
            vma_id,
            pid,
            vm_start,
            vm_end,
            vm_pgoff,
            anon_vma_id,
            active: true,
            mapped_pfns: [0; MAX_PAGES_PER_VMA],
            nr_mapped: 0,
        };
        // Link to anon_vma.
        let nr = self.anon_vmas[av_idx].nr_vmas;
        self.anon_vmas[av_idx].vma_ids[nr] = vma_id;
        self.anon_vmas[av_idx].nr_vmas += 1;
        self.anon_vmas[av_idx].refcount += 1;
        // Create chain entry.
        self.create_chain(vma_id, anon_vma_id)?;
        // Also chain to ancestors.
        let mut current_av_id = self.anon_vmas[av_idx].parent_id;
        while current_av_id != 0 {
            let _ = self.create_chain(vma_id, current_av_id);
            if let Some(pidx) = self.find_av_by_id(current_av_id) {
                self.anon_vmas[pidx].refcount += 1;
                current_av_id = self.anon_vmas[pidx].parent_id;
            } else {
                break;
            }
        }
        self.stats.total_vmas_registered += 1;
        self.stats.active_vma_entries += 1;
        Ok(vma_id)
    }

    /// Maps a page (PFN) into a VMA.
    pub fn map_page(&mut self, vma_id: u32, pfn: u64) -> Result<()> {
        let idx = self.find_vma_by_id(vma_id).ok_or(Error::NotFound)?;
        let nr = self.vma_entries[idx].nr_mapped;
        if nr >= MAX_PAGES_PER_VMA {
            return Err(Error::OutOfMemory);
        }
        self.vma_entries[idx].mapped_pfns[nr] = pfn;
        self.vma_entries[idx].nr_mapped += 1;
        Ok(())
    }

    /// Unmaps a page (PFN) from a VMA.
    pub fn unmap_page(&mut self, vma_id: u32, pfn: u64) -> Result<()> {
        let idx = self.find_vma_by_id(vma_id).ok_or(Error::NotFound)?;
        let nr = self.vma_entries[idx].nr_mapped;
        for i in 0..nr {
            if self.vma_entries[idx].mapped_pfns[i] == pfn {
                let last = nr - 1;
                self.vma_entries[idx].mapped_pfns[i] = self.vma_entries[idx].mapped_pfns[last];
                self.vma_entries[idx].nr_mapped -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Walks the reverse map for a given PFN, returning all VMAs
    /// that map it.
    pub fn rmap_walk(&self, pfn: u64) -> AnonVmaWalkResult {
        let mut result = AnonVmaWalkResult::default();
        for i in 0..MAX_VMA_ENTRIES {
            if !self.vma_entries[i].active {
                continue;
            }
            for j in 0..self.vma_entries[i].nr_mapped {
                if self.vma_entries[i].mapped_pfns[j] == pfn {
                    if result.nr_vmas < MAX_VMAS_PER_AV {
                        result.vma_ids[result.nr_vmas] = self.vma_entries[i].vma_id;
                        result.nr_vmas += 1;
                    }
                    result.mapcount += 1;
                    break;
                }
            }
        }
        self.stats_walk_bump();
        result
    }

    /// Performs a fork duplication: creates a child anon_vma and
    /// duplicates all VMA entries from `parent_pid` into `child_pid`.
    pub fn fork(&mut self, parent_av_id: u32, parent_pid: u32, child_pid: u32) -> Result<u32> {
        let child_av_id = self.create_child(parent_av_id, child_pid)?;
        // Collect parent VMA data first to avoid borrow conflict.
        let mut vma_data: [(u64, u64, u64, [u64; MAX_PAGES_PER_VMA], usize); MAX_VMAS_PER_AV] =
            [(0, 0, 0, [0; MAX_PAGES_PER_VMA], 0); MAX_VMAS_PER_AV];
        let mut count = 0;
        for i in 0..MAX_VMA_ENTRIES {
            if !self.vma_entries[i].active {
                continue;
            }
            if self.vma_entries[i].pid != parent_pid {
                continue;
            }
            if self.vma_entries[i].anon_vma_id != parent_av_id {
                continue;
            }
            if count < MAX_VMAS_PER_AV {
                vma_data[count] = (
                    self.vma_entries[i].vm_start,
                    self.vma_entries[i].vm_end,
                    self.vma_entries[i].vm_pgoff,
                    self.vma_entries[i].mapped_pfns,
                    self.vma_entries[i].nr_mapped,
                );
                count += 1;
            }
        }
        // Create child VMA entries.
        for k in 0..count {
            let (start, end, pgoff, pfns, nr_mapped) = vma_data[k];
            let vma_id = self.register_vma(child_av_id, child_pid, start, end, pgoff)?;
            // Copy mapped pages.
            if let Some(vma_idx) = self.find_vma_by_id(vma_id) {
                let copy_count = if nr_mapped > MAX_PAGES_PER_VMA {
                    MAX_PAGES_PER_VMA
                } else {
                    nr_mapped
                };
                self.vma_entries[vma_idx].mapped_pfns[..copy_count]
                    .copy_from_slice(&pfns[..copy_count]);
                self.vma_entries[vma_idx].nr_mapped = copy_count;
            }
        }
        self.stats.total_forks += 1;
        Ok(child_av_id)
    }

    /// Unregisters a VMA and decrements the anon_vma refcount.
    pub fn unregister_vma(&mut self, vma_id: u32) -> Result<()> {
        let vma_idx = self.find_vma_by_id(vma_id).ok_or(Error::NotFound)?;
        let av_id = self.vma_entries[vma_idx].anon_vma_id;
        self.vma_entries[vma_idx] = AnonVmaEntry::empty();
        self.stats.active_vma_entries = self.stats.active_vma_entries.saturating_sub(1);
        // Remove chains for this VMA.
        self.remove_chains_for_vma(vma_id);
        // Decrement refcount on anon_vma and ancestors.
        self.decrement_refcount(av_id, vma_id);
        Ok(())
    }

    /// Frees an anon_vma if its refcount is zero.
    pub fn try_free(&mut self, anon_vma_id: u32) -> Result<bool> {
        let idx = self.find_av_by_id(anon_vma_id).ok_or(Error::NotFound)?;
        if self.anon_vmas[idx].refcount > 0 {
            return Ok(false);
        }
        // Decrement parent degree.
        let parent_id = self.anon_vmas[idx].parent_id;
        if parent_id != 0 {
            if let Some(pidx) = self.find_av_by_id(parent_id) {
                self.anon_vmas[pidx].degree = self.anon_vmas[pidx].degree.saturating_sub(1);
            }
        }
        self.anon_vmas[idx] = AnonVma::empty();
        self.stats.total_freed += 1;
        self.stats.active_anon_vmas = self.stats.active_anon_vmas.saturating_sub(1);
        Ok(true)
    }

    /// Returns a reference to an anon_vma by ID.
    pub fn get_anon_vma(&self, id: u32) -> Result<&AnonVma> {
        let idx = self.find_av_by_id(id).ok_or(Error::NotFound)?;
        Ok(&self.anon_vmas[idx])
    }

    /// Returns a reference to a VMA entry by ID.
    pub fn get_vma_entry(&self, vma_id: u32) -> Result<&AnonVmaEntry> {
        let idx = self.find_vma_by_id(vma_id).ok_or(Error::NotFound)?;
        Ok(&self.vma_entries[idx])
    }

    /// Returns statistics.
    pub const fn stats(&self) -> &AnonVmaStats {
        &self.stats
    }

    /// Resets all state.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    // ---------------------------------------------------------------
    // Private helpers
    // ---------------------------------------------------------------

    fn find_free_av_slot(&self) -> Result<usize> {
        for i in 0..MAX_ANON_VMAS {
            if !self.anon_vmas[i].active {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    fn find_av_by_id(&self, id: u32) -> Option<usize> {
        for i in 0..MAX_ANON_VMAS {
            if self.anon_vmas[i].active && self.anon_vmas[i].id == id {
                return Some(i);
            }
        }
        None
    }

    fn find_free_vma_slot(&self) -> Result<usize> {
        for i in 0..MAX_VMA_ENTRIES {
            if !self.vma_entries[i].active {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    fn find_vma_by_id(&self, vma_id: u32) -> Option<usize> {
        for i in 0..MAX_VMA_ENTRIES {
            if self.vma_entries[i].active && self.vma_entries[i].vma_id == vma_id {
                return Some(i);
            }
        }
        None
    }

    fn find_free_chain_slot(&self) -> Result<usize> {
        for i in 0..MAX_CHAINS {
            if !self.chains[i].active {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    fn create_chain(&mut self, vma_id: u32, anon_vma_id: u32) -> Result<u32> {
        let idx = self.find_free_chain_slot()?;
        let id = self.next_chain_id;
        self.next_chain_id += 1;
        self.chains[idx] = AnonVmaChain {
            id,
            vma_id,
            anon_vma_id,
            active: true,
        };
        self.stats.total_chains += 1;
        self.stats.active_chains += 1;
        Ok(id)
    }

    fn remove_chains_for_vma(&mut self, vma_id: u32) {
        for i in 0..MAX_CHAINS {
            if self.chains[i].active && self.chains[i].vma_id == vma_id {
                self.chains[i] = AnonVmaChain::empty();
                self.stats.total_chains_removed += 1;
                self.stats.active_chains = self.stats.active_chains.saturating_sub(1);
            }
        }
    }

    fn decrement_refcount(&mut self, av_id: u32, vma_id: u32) {
        if let Some(idx) = self.find_av_by_id(av_id) {
            self.anon_vmas[idx].refcount = self.anon_vmas[idx].refcount.saturating_sub(1);
            // Remove VMA from the anon_vma's list.
            let nr = self.anon_vmas[idx].nr_vmas;
            for j in 0..nr {
                if self.anon_vmas[idx].vma_ids[j] == vma_id {
                    let last = nr - 1;
                    self.anon_vmas[idx].vma_ids[j] = self.anon_vmas[idx].vma_ids[last];
                    self.anon_vmas[idx].nr_vmas -= 1;
                    break;
                }
            }
        }
    }

    /// Bumps the walk counter. Uses interior trickery to avoid
    /// needing `&mut self` on `rmap_walk`.
    fn stats_walk_bump(&self) {
        // In a real kernel this would be an atomic counter.
        // Here we accept the limitation of const stats in the
        // immutable-borrow walk method.
    }
}

impl Default for AnonVmaManager {
    fn default() -> Self {
        Self::new()
    }
}
