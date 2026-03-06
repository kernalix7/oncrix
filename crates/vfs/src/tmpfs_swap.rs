// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! tmpfs swap-out support.
//!
//! tmpfs pages can be swapped out to disk under memory pressure. This module
//! implements the swap entry tracking, writepage / readpage paths, and the
//! shmem swaplist management used to reclaim tmpfs pages.
//!
//! # Design
//!
//! - [`TmpfsSwapEntry`] — maps a page index to a swap entry
//! - `shmem_writepage` — evict a page to swap
//! - `shmem_readpage` — swap a page back in on fault
//! - Swap accounting (pages in/out counts)
//! - Reclaim priority / swaplist management
//!
//! # References
//!
//! - Linux `mm/shmem.c`
//! - Linux `include/linux/swap.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum swap entries tracked (one per swapped-out page).
pub const MAX_SWAP_ENTRIES: usize = 4096;

/// Maximum tmpfs inodes tracked.
pub const MAX_TMPFS_INODES: usize = 256;

/// Swap entry is invalid / not swapped.
pub const SWP_ENTRY_NONE: u64 = 0;

/// Swap slot size in pages.
pub const SWAP_SLOT_SIZE: usize = 1;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A mapping from a page index within a tmpfs inode to a swap slot.
#[derive(Debug, Clone, Copy, Default)]
pub struct TmpfsSwapEntry {
    /// Inode number.
    pub inode: u64,
    /// Page index within the inode (offset / PAGE_SIZE).
    pub page_index: u64,
    /// Swap entry (type | offset encoding).
    pub swap_entry: u64,
    /// Slot in use.
    pub in_use: bool,
}

/// Swap accounting counters.
#[derive(Debug, Clone, Copy, Default)]
pub struct SwapAccounting {
    /// Pages written to swap.
    pub pages_out: u64,
    /// Pages read back from swap.
    pub pages_in: u64,
    /// Pages currently in swap.
    pub pages_in_swap: u64,
    /// Swap-in faults (page not present, needed from swap).
    pub swap_faults: u64,
}

/// Per-inode swap state.
#[derive(Clone, Copy)]
struct InodeSwapState {
    inode: u64,
    pages_swapped: u32,
    reclaim_priority: u8,
    in_swaplist: bool,
    in_use: bool,
}

impl InodeSwapState {
    const fn empty() -> Self {
        Self {
            inode: 0,
            pages_swapped: 0,
            reclaim_priority: 0,
            in_swaplist: false,
            in_use: false,
        }
    }
}

/// Global tmpfs swap state.
pub struct TmpfsSwapState {
    /// Swap entry table (inode + page_index → swap_entry).
    entries: [TmpfsSwapEntry; MAX_SWAP_ENTRIES],
    /// Per-inode state.
    inodes: [InodeSwapState; MAX_TMPFS_INODES],
    /// Accounting.
    pub accounting: SwapAccounting,
    /// Next synthetic swap entry value.
    next_swap_entry: u64,
}

impl TmpfsSwapState {
    /// Create an empty swap state.
    pub fn new() -> Self {
        Self {
            entries: [TmpfsSwapEntry::default(); MAX_SWAP_ENTRIES],
            inodes: [InodeSwapState::empty(); MAX_TMPFS_INODES],
            accounting: SwapAccounting::default(),
            next_swap_entry: 1,
        }
    }

    fn find_entry(&self, inode: u64, page_index: u64) -> Option<usize> {
        for i in 0..MAX_SWAP_ENTRIES {
            if self.entries[i].in_use
                && self.entries[i].inode == inode
                && self.entries[i].page_index == page_index
            {
                return Some(i);
            }
        }
        None
    }

    fn free_entry_slot(&self) -> Option<usize> {
        for i in 0..MAX_SWAP_ENTRIES {
            if !self.entries[i].in_use {
                return Some(i);
            }
        }
        None
    }

    fn find_inode_state(&self, inode: u64) -> Option<usize> {
        for i in 0..MAX_TMPFS_INODES {
            if self.inodes[i].in_use && self.inodes[i].inode == inode {
                return Some(i);
            }
        }
        None
    }

    fn get_or_create_inode_state(&mut self, inode: u64) -> Option<usize> {
        if let Some(idx) = self.find_inode_state(inode) {
            return Some(idx);
        }
        for i in 0..MAX_TMPFS_INODES {
            if !self.inodes[i].in_use {
                self.inodes[i] = InodeSwapState {
                    inode,
                    pages_swapped: 0,
                    reclaim_priority: 128,
                    in_swaplist: false,
                    in_use: true,
                };
                return Some(i);
            }
        }
        None
    }

    fn alloc_swap_entry(&mut self) -> u64 {
        let entry = self.next_swap_entry;
        self.next_swap_entry += 1;
        entry
    }
}

impl Default for TmpfsSwapState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Write (swap out) a page from inode `inode` at `page_index`.
///
/// Allocates a swap entry, records the mapping, and returns the swap entry
/// value. The caller is responsible for actually writing the page data to the
/// swap device.
pub fn shmem_writepage(state: &mut TmpfsSwapState, inode: u64, page_index: u64) -> Result<u64> {
    // Check not already swapped.
    if state.find_entry(inode, page_index).is_some() {
        return Err(Error::AlreadyExists);
    }
    let slot = state.free_entry_slot().ok_or(Error::OutOfMemory)?;
    let swap_entry = state.alloc_swap_entry();

    state.entries[slot] = TmpfsSwapEntry {
        inode,
        page_index,
        swap_entry,
        in_use: true,
    };
    state.accounting.pages_out += 1;
    state.accounting.pages_in_swap += 1;

    // Update per-inode state.
    if let Some(idx) = state.get_or_create_inode_state(inode) {
        state.inodes[idx].pages_swapped += 1;
        if !state.inodes[idx].in_swaplist {
            state.inodes[idx].in_swaplist = true;
        }
    }
    Ok(swap_entry)
}

/// Read (swap in) a page for inode `inode` at `page_index`.
///
/// Returns the swap entry that was holding the page. The caller must read
/// the actual page data from the swap device using this entry.
/// After this call the swap mapping is cleared.
pub fn shmem_readpage(state: &mut TmpfsSwapState, inode: u64, page_index: u64) -> Result<u64> {
    let slot = state.find_entry(inode, page_index).ok_or(Error::NotFound)?;
    let swap_entry = state.entries[slot].swap_entry;
    // Remove the mapping.
    state.entries[slot] = TmpfsSwapEntry::default();
    state.accounting.pages_in += 1;
    state.accounting.pages_in_swap = state.accounting.pages_in_swap.saturating_sub(1);
    state.accounting.swap_faults += 1;

    // Update per-inode state.
    if let Some(idx) = state.find_inode_state(inode) {
        state.inodes[idx].pages_swapped = state.inodes[idx].pages_swapped.saturating_sub(1);
        if state.inodes[idx].pages_swapped == 0 {
            state.inodes[idx].in_swaplist = false;
        }
    }
    Ok(swap_entry)
}

/// Check whether a page is currently in swap.
pub fn is_swapped(state: &TmpfsSwapState, inode: u64, page_index: u64) -> bool {
    state.find_entry(inode, page_index).is_some()
}

/// Return the swap entry for a swapped-out page, or `SWP_ENTRY_NONE`.
pub fn get_swap_entry(state: &TmpfsSwapState, inode: u64, page_index: u64) -> u64 {
    state
        .find_entry(inode, page_index)
        .map_or(SWP_ENTRY_NONE, |i| state.entries[i].swap_entry)
}

/// Set the reclaim priority for `inode` (higher = less likely to be reclaimed).
///
/// Priority is in range 0–255.
pub fn set_reclaim_priority(state: &mut TmpfsSwapState, inode: u64, priority: u8) -> Result<()> {
    let idx = state
        .get_or_create_inode_state(inode)
        .ok_or(Error::OutOfMemory)?;
    state.inodes[idx].reclaim_priority = priority;
    Ok(())
}

/// Collect inodes in the swaplist sorted by reclaim priority.
///
/// Returns inode IDs in ascending priority order (lowest priority first).
/// Fills `out` with up to `out.len()` inodes. Returns count written.
pub fn shmem_swaplist_scan(state: &TmpfsSwapState, out: &mut [u64]) -> usize {
    // Collect inodes that are in the swaplist.
    let mut candidates = [(0u64, 0u8); MAX_TMPFS_INODES];
    let mut ccount = 0;
    for i in 0..MAX_TMPFS_INODES {
        if state.inodes[i].in_use && state.inodes[i].in_swaplist {
            candidates[ccount] = (state.inodes[i].inode, state.inodes[i].reclaim_priority);
            ccount += 1;
        }
    }
    // Sort by priority (low priority = reclaim first).
    for i in 0..ccount {
        for j in i + 1..ccount {
            if candidates[j].1 < candidates[i].1 {
                candidates.swap(i, j);
            }
        }
    }
    let write = ccount.min(out.len());
    for i in 0..write {
        out[i] = candidates[i].0;
    }
    write
}

/// Purge all swap entries for a deleted inode.
///
/// Returns the number of swap entries freed.
pub fn purge_inode_swap(state: &mut TmpfsSwapState, inode: u64) -> usize {
    let mut freed = 0;
    for i in 0..MAX_SWAP_ENTRIES {
        if state.entries[i].in_use && state.entries[i].inode == inode {
            state.entries[i] = TmpfsSwapEntry::default();
            state.accounting.pages_in_swap = state.accounting.pages_in_swap.saturating_sub(1);
            freed += 1;
        }
    }
    if let Some(idx) = state.find_inode_state(inode) {
        state.inodes[idx] = InodeSwapState::empty();
    }
    freed
}

/// Return swap accounting snapshot.
pub fn swap_accounting(state: &TmpfsSwapState) -> &SwapAccounting {
    &state.accounting
}
