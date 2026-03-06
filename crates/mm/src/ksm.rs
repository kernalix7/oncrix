// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel Same-page Merging (KSM) subsystem.
//!
//! Scans registered anonymous pages for identical content, merges
//! duplicates into a single copy-on-write page, and tracks reverse
//! mappings so that CoW breaks can allocate fresh copies when a
//! process writes to a merged page.
//!
//! - [`KsmScanner`] — main scanner engine with stable/unstable trees
//! - [`KsmPage`] — per-page metadata including hash, state, and rmaps
//! - [`KsmStableNode`] — sorted node for binary-search lookup of merged pages
//! - [`KsmUnstableTree`] — pool of scanned-but-unmatched page indices
//! - [`KsmStats`] — aggregate merging statistics

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of pages the KSM scanner can track.
const MAX_KSM_PAGES: usize = 1024;

/// Maximum number of stable (merged) nodes.
const MAX_STABLE_NODES: usize = 256;

/// Maximum number of entries in the unstable tree.
const MAX_UNSTABLE_PAGES: usize = 512;

/// Maximum reverse mappings per KSM page.
const MAX_RMAP_PER_PAGE: usize = 8;

/// FNV-1a offset basis (64-bit).
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;

/// FNV-1a prime (64-bit).
const FNV_PRIME: u64 = 0x0100_0000_01b3;

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: usize = 4096;

// -------------------------------------------------------------------
// KsmPageState
// -------------------------------------------------------------------

/// Lifecycle state of a page tracked by KSM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KsmPageState {
    /// Page has not yet been scanned.
    #[default]
    Unscanned,
    /// Page was scanned but no match was found yet (in unstable tree).
    Unstable,
    /// Page matched another and is the canonical (kept) copy.
    Stable,
    /// Page has been replaced by a CoW reference to a stable page.
    Merged,
}

// -------------------------------------------------------------------
// KsmRmap
// -------------------------------------------------------------------

/// Reverse mapping entry: identifies one virtual mapping of a KSM page.
#[derive(Debug, Clone, Copy, Default)]
pub struct KsmRmap {
    /// Process ID that maps this page.
    pub pid: u64,
    /// Virtual address in the process's address space.
    pub vaddr: u64,
}

// -------------------------------------------------------------------
// KsmPage
// -------------------------------------------------------------------

/// Per-page metadata for KSM tracking.
#[derive(Debug, Clone, Copy)]
pub struct KsmPage {
    /// Physical address of the page.
    pub phys_addr: u64,
    /// Content hash (FNV-1a over page bytes).
    pub hash: u64,
    /// Current KSM lifecycle state.
    pub state: KsmPageState,
    /// Number of processes sharing this page via CoW.
    pub ref_count: u32,
    /// Reverse mappings for CoW break notifications.
    pub rmap: [KsmRmap; MAX_RMAP_PER_PAGE],
    /// Number of valid entries in `rmap`.
    pub rmap_count: usize,
}

impl KsmPage {
    /// Creates an empty, zeroed KSM page descriptor.
    const fn empty() -> Self {
        Self {
            phys_addr: 0,
            hash: 0,
            state: KsmPageState::Unscanned,
            ref_count: 0,
            rmap: [KsmRmap { pid: 0, vaddr: 0 }; MAX_RMAP_PER_PAGE],
            rmap_count: 0,
        }
    }
}

// -------------------------------------------------------------------
// KsmStableNode
// -------------------------------------------------------------------

/// Entry in the stable tree, sorted by content hash for binary search.
#[derive(Debug, Clone, Copy, Default)]
pub struct KsmStableNode {
    /// Index into the KsmScanner page pool.
    pub page_idx: u16,
    /// Content hash of the stable page.
    pub hash: u64,
    /// Whether this node is actively in use.
    pub in_use: bool,
}

// -------------------------------------------------------------------
// KsmUnstableTree
// -------------------------------------------------------------------

/// Collection of page indices that have been scanned but not yet
/// matched against a stable page or another unstable page.
#[derive(Debug, Clone, Copy)]
pub struct KsmUnstableTree {
    /// Indices into the KsmScanner page pool.
    pub pages: [u16; MAX_UNSTABLE_PAGES],
    /// Number of valid entries.
    pub count: usize,
}

impl Default for KsmUnstableTree {
    fn default() -> Self {
        Self {
            pages: [0; MAX_UNSTABLE_PAGES],
            count: 0,
        }
    }
}

// -------------------------------------------------------------------
// KsmStats
// -------------------------------------------------------------------

/// Aggregate KSM merging statistics (mirrors `/sys/kernel/mm/ksm/`).
#[derive(Debug, Clone, Copy, Default)]
pub struct KsmStats {
    /// Number of pages that are the canonical stable copy.
    pub pages_shared: u64,
    /// Number of virtual mappings pointing to shared pages.
    pub pages_sharing: u64,
    /// Number of pages scanned but unique (no duplicate found).
    pub pages_unshared: u64,
    /// Number of full scan cycles completed.
    pub full_scans: u64,
    /// Number of pages whose content changed between scans.
    pub pages_volatile: u64,
    /// Whether merging is allowed across NUMA nodes.
    pub merge_across_nodes: bool,
}

// -------------------------------------------------------------------
// KsmScanner
// -------------------------------------------------------------------

/// Main KSM engine that scans pages, detects duplicates, and merges
/// them into copy-on-write shared pages.
pub struct KsmScanner {
    /// Stable tree: merged pages sorted by hash.
    stable_nodes: [KsmStableNode; MAX_STABLE_NODES],
    /// Number of active stable nodes.
    stable_count: usize,
    /// Unstable tree: scanned-but-unmatched pages.
    unstable: KsmUnstableTree,
    /// Page pool for all tracked pages.
    pages: [KsmPage; MAX_KSM_PAGES],
    /// Number of registered pages.
    page_count: usize,
    /// Current scan position in the page pool.
    scan_cursor: usize,
    /// Milliseconds to sleep between scan batches.
    sleep_ms: u64,
    /// Whether the scanner is enabled.
    enabled: bool,
    /// Aggregate statistics.
    stats: KsmStats,
}

impl Default for KsmScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl KsmScanner {
    /// Creates a new, disabled KSM scanner with empty pools.
    pub const fn new() -> Self {
        Self {
            stable_nodes: [KsmStableNode {
                page_idx: 0,
                hash: 0,
                in_use: false,
            }; MAX_STABLE_NODES],
            stable_count: 0,
            unstable: KsmUnstableTree {
                pages: [0; MAX_UNSTABLE_PAGES],
                count: 0,
            },
            pages: [KsmPage::empty(); MAX_KSM_PAGES],
            page_count: 0,
            scan_cursor: 0,
            sleep_ms: 200,
            enabled: false,
            stats: KsmStats {
                pages_shared: 0,
                pages_sharing: 0,
                pages_unshared: 0,
                full_scans: 0,
                pages_volatile: 0,
                merge_across_nodes: true,
            },
        }
    }

    /// Registers a page for KSM scanning.
    ///
    /// # Arguments
    ///
    /// - `phys_addr`: physical address of the 4 KiB page
    /// - `pid`: process ID that owns the mapping
    /// - `vaddr`: virtual address in the process's address space
    ///
    /// # Returns
    ///
    /// The page index within the scanner's pool.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the page pool is full.
    pub fn register_page(&mut self, phys_addr: u64, pid: u64, vaddr: u64) -> Result<u16> {
        if self.page_count >= MAX_KSM_PAGES {
            return Err(Error::OutOfMemory);
        }

        let idx = self.page_count;
        self.pages[idx] = KsmPage {
            phys_addr,
            hash: 0,
            state: KsmPageState::Unscanned,
            ref_count: 1,
            rmap: [KsmRmap { pid: 0, vaddr: 0 }; MAX_RMAP_PER_PAGE],
            rmap_count: 1,
        };
        self.pages[idx].rmap[0] = KsmRmap { pid, vaddr };
        self.page_count += 1;

        Ok(idx as u16)
    }

    /// Unregisters a page from KSM tracking.
    ///
    /// If the page was in the stable or unstable tree, it is removed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `page_idx` is out of range.
    pub fn unregister_page(&mut self, page_idx: u16) -> Result<()> {
        let idx = page_idx as usize;
        if idx >= self.page_count {
            return Err(Error::InvalidArgument);
        }

        let state = self.pages[idx].state;

        // Remove from stable tree if present.
        if state == KsmPageState::Stable {
            self.remove_stable(page_idx);
            self.stats.pages_shared = self.stats.pages_shared.saturating_sub(1);
        }

        // Remove from unstable tree if present.
        if state == KsmPageState::Unstable {
            self.remove_unstable(page_idx);
            self.stats.pages_unshared = self.stats.pages_unshared.saturating_sub(1);
        }

        if state == KsmPageState::Merged {
            self.stats.pages_sharing = self.stats.pages_sharing.saturating_sub(1);
        }

        // Swap with the last page to keep the pool compact.
        let last = self.page_count - 1;
        if idx != last {
            self.pages[idx] = self.pages[last];
            // Update references in stable/unstable trees.
            self.reindex_page(last as u16, page_idx);
        }
        self.pages[last] = KsmPage::empty();
        self.page_count -= 1;

        // Adjust scan cursor if needed.
        if self.scan_cursor > 0 && self.scan_cursor >= self.page_count {
            self.scan_cursor = 0;
        }

        Ok(())
    }

    /// Computes an FNV-1a-like content hash for a page.
    ///
    /// In a real kernel this would hash the page's physical memory
    /// contents. Here we use the physical address as a deterministic
    /// placeholder to avoid dereferencing raw pointers.
    pub fn compute_hash(&self, page_idx: u16) -> u64 {
        let idx = page_idx as usize;
        if idx >= self.page_count {
            return 0;
        }

        let addr = self.pages[idx].phys_addr;

        // Simulate hashing PAGE_SIZE bytes by folding the address.
        let mut hash = FNV_OFFSET_BASIS;
        let mut i = 0;
        while i < PAGE_SIZE {
            let byte = ((addr >> ((i % 8) * 8)) & 0xFF) as u8;
            hash ^= byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
            i += 1;
        }
        hash
    }

    /// Performs one scan step, processing up to `batch_size` pages.
    ///
    /// For each page the scanner:
    /// 1. Computes its content hash
    /// 2. Checks the stable tree for an existing match
    /// 3. If no stable match, checks the unstable tree
    /// 4. If a match is found, merges the pages
    ///
    /// # Returns
    ///
    /// The number of pages actually processed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotSupported`] if the scanner is disabled.
    pub fn scan_step(&mut self, batch_size: usize) -> Result<u32> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }

        if self.page_count == 0 {
            return Ok(0);
        }

        let mut processed = 0_u32;

        for _ in 0..batch_size {
            if self.page_count == 0 {
                break;
            }

            // Wrap cursor around for a full scan.
            if self.scan_cursor >= self.page_count {
                self.scan_cursor = 0;
                self.stats.full_scans += 1;
                // Clear unstable tree at the start of each full scan.
                self.clear_unstable();
            }

            let cursor = self.scan_cursor;
            let page_idx = cursor as u16;

            // Skip pages that are already merged or stable.
            let state = self.pages[cursor].state;
            if state == KsmPageState::Merged || state == KsmPageState::Stable {
                self.scan_cursor += 1;
                processed += 1;
                continue;
            }

            // Compute and store hash.
            let old_hash = self.pages[cursor].hash;
            let new_hash = self.compute_hash(page_idx);
            self.pages[cursor].hash = new_hash;

            // Detect volatile pages (content changed since last scan).
            if state == KsmPageState::Unstable && old_hash != new_hash {
                self.remove_unstable(page_idx);
                self.pages[cursor].state = KsmPageState::Unscanned;
                self.stats.pages_volatile += 1;
                self.scan_cursor += 1;
                processed += 1;
                continue;
            }

            // Check stable tree first.
            if let Some(stable_idx) = self.find_stable(new_hash) {
                // Merge this page into the stable page.
                let _ = self.try_merge(stable_idx, page_idx);
                self.scan_cursor += 1;
                processed += 1;
                continue;
            }

            // Check unstable tree for a match.
            if let Some(unstable_match) = self.find_unstable(new_hash) {
                // Promote the unstable match to stable and merge.
                self.remove_unstable(unstable_match);
                self.pages[unstable_match as usize].state = KsmPageState::Stable;
                self.add_stable(unstable_match, new_hash);
                self.stats.pages_shared += 1;
                self.stats.pages_unshared = self.stats.pages_unshared.saturating_sub(1);

                let _ = self.try_merge(unstable_match, page_idx);
                self.scan_cursor += 1;
                processed += 1;
                continue;
            }

            // No match — add to unstable tree.
            self.pages[cursor].state = KsmPageState::Unstable;
            self.add_unstable(page_idx);
            self.stats.pages_unshared += 1;

            self.scan_cursor += 1;
            processed += 1;
        }

        Ok(processed)
    }

    /// Attempts to merge two pages with identical content.
    ///
    /// Page `page_b` is marked as `Merged` and its reverse mappings
    /// are added to `page_a`. In a real kernel this would remap
    /// `page_b`'s virtual mappings to `page_a`'s physical frame
    /// as CoW.
    ///
    /// # Returns
    ///
    /// `true` if the merge succeeded.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if either index is out of
    /// range or the hashes do not match.
    pub fn try_merge(&mut self, page_a: u16, page_b: u16) -> Result<bool> {
        let a = page_a as usize;
        let b = page_b as usize;

        if a >= self.page_count || b >= self.page_count {
            return Err(Error::InvalidArgument);
        }

        if a == b {
            return Ok(false);
        }

        if self.pages[a].hash != self.pages[b].hash {
            return Err(Error::InvalidArgument);
        }

        // Transfer reverse mappings from page_b to page_a.
        let b_rmap_count = self.pages[b].rmap_count;
        for i in 0..b_rmap_count {
            let rmap = self.pages[b].rmap[i];
            let a_rcount = self.pages[a].rmap_count;
            if a_rcount < MAX_RMAP_PER_PAGE {
                self.pages[a].rmap[a_rcount] = rmap;
                self.pages[a].rmap_count += 1;
            }
        }

        self.pages[a].ref_count = self.pages[a].ref_count.saturating_add(1);
        self.pages[b].state = KsmPageState::Merged;

        // Remove page_b from unstable tree if present.
        self.remove_unstable(page_b);

        self.stats.pages_sharing += 1;

        Ok(true)
    }

    /// Breaks a CoW sharing for a specific process on a merged page.
    ///
    /// Simulates allocating a new physical frame for the process and
    /// removing its reverse mapping from the shared page. Returns
    /// the "new" physical address (stub: original address + 0x1000).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the page index is out
    /// of range, or [`Error::NotFound`] if the pid has no mapping
    /// on this page.
    pub fn break_cow(&mut self, page_idx: u16, pid: u64) -> Result<u64> {
        let idx = page_idx as usize;
        if idx >= self.page_count {
            return Err(Error::InvalidArgument);
        }

        // Find and remove the rmap entry for this pid.
        let mut found = false;
        let rmap_count = self.pages[idx].rmap_count;

        for i in 0..rmap_count {
            if self.pages[idx].rmap[i].pid == pid {
                // Shift remaining entries down.
                let mut j = i;
                while j + 1 < rmap_count {
                    self.pages[idx].rmap[j] = self.pages[idx].rmap[j + 1];
                    j += 1;
                }
                self.pages[idx].rmap[rmap_count - 1] = KsmRmap::default();
                self.pages[idx].rmap_count -= 1;
                self.pages[idx].ref_count = self.pages[idx].ref_count.saturating_sub(1);
                found = true;
                break;
            }
        }

        if !found {
            return Err(Error::NotFound);
        }

        self.stats.pages_sharing = self.stats.pages_sharing.saturating_sub(1);

        // If only one mapping remains, the page is no longer shared.
        if self.pages[idx].ref_count <= 1 {
            if self.pages[idx].state == KsmPageState::Stable {
                self.remove_stable(page_idx);
                self.stats.pages_shared = self.stats.pages_shared.saturating_sub(1);
            }
            self.pages[idx].state = KsmPageState::Unscanned;
        }

        // Stub: return a "new" physical address.
        let new_phys = self.pages[idx].phys_addr.wrapping_add(PAGE_SIZE as u64);
        Ok(new_phys)
    }

    /// Searches the stable tree for a page with the given hash.
    ///
    /// Uses binary search on the sorted stable nodes.
    ///
    /// # Returns
    ///
    /// The page pool index of the matching stable page, or `None`.
    pub fn find_stable(&self, hash: u64) -> Option<u16> {
        if self.stable_count == 0 {
            return None;
        }

        // Binary search on sorted stable nodes.
        let mut lo = 0_usize;
        let mut hi = self.stable_count;

        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let node = &self.stable_nodes[mid];

            if !node.in_use {
                lo = mid + 1;
                continue;
            }

            if node.hash == hash {
                return Some(node.page_idx);
            } else if node.hash < hash {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }

        None
    }

    /// Returns a reference to the aggregate KSM statistics.
    pub fn get_stats(&self) -> &KsmStats {
        &self.stats
    }

    /// Sets the sleep interval between scan batches (in milliseconds).
    pub fn set_sleep_ms(&mut self, ms: u64) {
        self.sleep_ms = ms;
    }

    /// Enables the KSM scanner.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disables the KSM scanner.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Returns the number of registered pages.
    pub fn len(&self) -> usize {
        self.page_count
    }

    /// Returns `true` if no pages are registered.
    pub fn is_empty(&self) -> bool {
        self.page_count == 0
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    /// Adds a page to the stable tree, maintaining sort order by hash.
    fn add_stable(&mut self, page_idx: u16, hash: u64) {
        if self.stable_count >= MAX_STABLE_NODES {
            return;
        }

        // Find insertion point to keep sorted order.
        let mut pos = self.stable_count;
        for i in 0..self.stable_count {
            if self.stable_nodes[i].hash > hash {
                pos = i;
                break;
            }
        }

        // Shift elements right.
        let mut i = self.stable_count;
        while i > pos {
            self.stable_nodes[i] = self.stable_nodes[i - 1];
            i -= 1;
        }

        self.stable_nodes[pos] = KsmStableNode {
            page_idx,
            hash,
            in_use: true,
        };
        self.stable_count += 1;
    }

    /// Removes a page from the stable tree.
    fn remove_stable(&mut self, page_idx: u16) {
        for i in 0..self.stable_count {
            if self.stable_nodes[i].page_idx == page_idx && self.stable_nodes[i].in_use {
                // Shift elements left.
                let mut j = i;
                while j + 1 < self.stable_count {
                    self.stable_nodes[j] = self.stable_nodes[j + 1];
                    j += 1;
                }
                self.stable_nodes[self.stable_count - 1] = KsmStableNode::default();
                self.stable_count -= 1;
                return;
            }
        }
    }

    /// Adds a page index to the unstable tree.
    fn add_unstable(&mut self, page_idx: u16) {
        if self.unstable.count >= MAX_UNSTABLE_PAGES {
            return;
        }
        self.unstable.pages[self.unstable.count] = page_idx;
        self.unstable.count += 1;
    }

    /// Removes a page index from the unstable tree.
    fn remove_unstable(&mut self, page_idx: u16) {
        for i in 0..self.unstable.count {
            if self.unstable.pages[i] == page_idx {
                let mut j = i;
                while j + 1 < self.unstable.count {
                    self.unstable.pages[j] = self.unstable.pages[j + 1];
                    j += 1;
                }
                self.unstable.count -= 1;
                return;
            }
        }
    }

    /// Finds a page in the unstable tree with a matching hash.
    fn find_unstable(&self, hash: u64) -> Option<u16> {
        for i in 0..self.unstable.count {
            let page_idx = self.unstable.pages[i] as usize;
            if page_idx < self.page_count && self.pages[page_idx].hash == hash {
                return Some(self.unstable.pages[i]);
            }
        }
        None
    }

    /// Clears all entries from the unstable tree and resets
    /// their state to `Unscanned`.
    fn clear_unstable(&mut self) {
        for i in 0..self.unstable.count {
            let page_idx = self.unstable.pages[i] as usize;
            if page_idx < self.page_count && self.pages[page_idx].state == KsmPageState::Unstable {
                self.pages[page_idx].state = KsmPageState::Unscanned;
            }
        }
        self.stats.pages_unshared = 0;
        self.unstable.count = 0;
    }

    /// Updates stable/unstable tree references when a page is
    /// moved within the pool (during unregister compaction).
    fn reindex_page(&mut self, old_idx: u16, new_idx: u16) {
        // Update stable tree.
        for i in 0..self.stable_count {
            if self.stable_nodes[i].page_idx == old_idx {
                self.stable_nodes[i].page_idx = new_idx;
                break;
            }
        }

        // Update unstable tree.
        for i in 0..self.unstable.count {
            if self.unstable.pages[i] == old_idx {
                self.unstable.pages[i] = new_idx;
                break;
            }
        }
    }
}
