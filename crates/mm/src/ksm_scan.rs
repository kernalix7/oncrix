// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! KSM (Kernel Same-page Merging) page scanning.
//!
//! Implements the KSM scanning engine that finds identical pages
//! across different processes and merges them into a single
//! copy-on-write page. Uses a two-tree approach: pages are first
//! placed in an unstable tree; when a match is found, both pages
//! move to the stable tree.
//!
//! - [`KsmScanState`] — scanner cursor and configuration
//! - [`KsmRmapItem`] — reverse mapping for a scanned page
//! - [`StableNode`] — node in the stable (merged) tree
//! - [`UnstableEntry`] — entry in the unstable (candidate) tree
//! - [`KsmScanner`] — the main KSM scanning engine
//! - [`KsmScanStats`] — aggregate statistics
//!
//! Reference: `.kernelORG/` — `mm/ksm.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Maximum number of rmap items.
const MAX_RMAP_ITEMS: usize = 512;

/// Maximum number of stable nodes.
const MAX_STABLE_NODES: usize = 128;

/// Maximum number of unstable entries.
const MAX_UNSTABLE_ENTRIES: usize = 256;

/// Maximum rmaps per stable node.
const MAX_RMAPS_PER_NODE: usize = 8;

/// FNV-1a offset basis.
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;

/// FNV-1a prime.
const FNV_PRIME: u64 = 0x0100_0000_01b3;

/// Default pages to scan per pass.
const DEFAULT_PAGES_TO_SCAN: usize = 100;

// -------------------------------------------------------------------
// KsmRmapItem
// -------------------------------------------------------------------

/// Reverse mapping item: identifies one virtual mapping of a page.
#[derive(Debug, Clone, Copy, Default)]
pub struct KsmRmapItem {
    /// Process ID.
    pub pid: u64,
    /// Virtual address in the process.
    pub vaddr: u64,
    /// Page frame number.
    pub pfn: u64,
    /// Content hash of the page.
    pub hash: u64,
    /// Whether this item is active.
    pub active: bool,
}

// -------------------------------------------------------------------
// StableNode
// -------------------------------------------------------------------

/// Node in the stable (merged) tree.
///
/// A stable node represents a unique page content that is shared by
/// one or more processes via CoW mappings.
#[derive(Debug, Clone, Copy)]
pub struct StableNode {
    /// Content hash (key for sorted lookup).
    pub hash: u64,
    /// PFN of the canonical (shared) page.
    pub pfn: u64,
    /// Rmap list: processes sharing this page.
    pub rmaps: [KsmRmapItem; MAX_RMAPS_PER_NODE],
    /// Number of rmaps.
    pub rmap_count: usize,
    /// Whether this node is in use.
    pub active: bool,
}

impl Default for StableNode {
    fn default() -> Self {
        Self {
            hash: 0,
            pfn: 0,
            rmaps: [KsmRmapItem::default(); MAX_RMAPS_PER_NODE],
            rmap_count: 0,
            active: false,
        }
    }
}

impl StableNode {
    /// Creates a new stable node.
    pub fn new(hash: u64, pfn: u64) -> Self {
        Self {
            hash,
            pfn,
            active: true,
            ..Self::default()
        }
    }

    /// Adds an rmap to this node.
    pub fn add_rmap(&mut self, item: KsmRmapItem) -> Result<()> {
        if self.rmap_count >= MAX_RMAPS_PER_NODE {
            return Err(Error::OutOfMemory);
        }
        self.rmaps[self.rmap_count] = item;
        self.rmap_count += 1;
        Ok(())
    }

    /// Returns the number of rmaps (sharing count).
    pub fn sharing_count(&self) -> usize {
        self.rmap_count
    }
}

// -------------------------------------------------------------------
// UnstableEntry
// -------------------------------------------------------------------

/// Entry in the unstable (candidate) tree.
///
/// Pages are placed here after scanning; if a match is found, both
/// move to the stable tree.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnstableEntry {
    /// Content hash.
    pub hash: u64,
    /// PFN of the page.
    pub pfn: u64,
    /// Rmap item.
    pub rmap: KsmRmapItem,
    /// Whether this entry is active.
    pub active: bool,
}

// -------------------------------------------------------------------
// KsmScanStats
// -------------------------------------------------------------------

/// Aggregate KSM scan statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct KsmScanStats {
    /// Pages scanned.
    pub pages_scanned: u64,
    /// Pages found identical (merged).
    pub pages_shared: u64,
    /// Total sharing instances (rmaps to shared pages).
    pub pages_sharing: u64,
    /// Pages scanned but not matching anything.
    pub pages_unshared: u64,
    /// Full scans completed.
    pub full_scans: u64,
    /// Stable tree insert operations.
    pub stable_inserts: u64,
    /// Unstable tree insert operations.
    pub unstable_inserts: u64,
    /// Merge operations.
    pub merges: u64,
}

impl KsmScanStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// KsmScanner
// -------------------------------------------------------------------

/// The main KSM scanning engine.
pub struct KsmScanner {
    /// Stable tree (sorted by hash).
    stable: [StableNode; MAX_STABLE_NODES],
    /// Number of active stable nodes.
    stable_count: usize,
    /// Unstable tree (candidates).
    unstable: [UnstableEntry; MAX_UNSTABLE_ENTRIES],
    /// Number of active unstable entries.
    unstable_count: usize,
    /// Rmap item pool (pages registered for scanning).
    rmap_pool: [KsmRmapItem; MAX_RMAP_ITEMS],
    /// Number of rmap items in the pool.
    rmap_pool_count: usize,
    /// Scan cursor (index into rmap_pool).
    cursor: usize,
    /// Pages to scan per pass.
    pages_to_scan: usize,
    /// Statistics.
    stats: KsmScanStats,
}

impl Default for KsmScanner {
    fn default() -> Self {
        Self {
            stable: [const {
                StableNode {
                    hash: 0,
                    pfn: 0,
                    rmaps: [KsmRmapItem {
                        pid: 0,
                        vaddr: 0,
                        pfn: 0,
                        hash: 0,
                        active: false,
                    }; MAX_RMAPS_PER_NODE],
                    rmap_count: 0,
                    active: false,
                }
            }; MAX_STABLE_NODES],
            stable_count: 0,
            unstable: [UnstableEntry::default(); MAX_UNSTABLE_ENTRIES],
            unstable_count: 0,
            rmap_pool: [KsmRmapItem::default(); MAX_RMAP_ITEMS],
            rmap_pool_count: 0,
            cursor: 0,
            pages_to_scan: DEFAULT_PAGES_TO_SCAN,
            stats: KsmScanStats::default(),
        }
    }
}

impl KsmScanner {
    /// Creates a new KSM scanner.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the number of pages to scan per pass.
    pub fn set_pages_to_scan(&mut self, count: usize) {
        self.pages_to_scan = count;
    }

    /// Registers a page for KSM scanning.
    pub fn register_page(&mut self, pid: u64, vaddr: u64, pfn: u64, data: &[u8]) -> Result<usize> {
        if self.rmap_pool_count >= MAX_RMAP_ITEMS {
            return Err(Error::OutOfMemory);
        }
        let hash = Self::hash_page(data);
        let idx = self.rmap_pool_count;
        self.rmap_pool[idx] = KsmRmapItem {
            pid,
            vaddr,
            pfn,
            hash,
            active: true,
        };
        self.rmap_pool_count += 1;
        Ok(idx)
    }

    /// Performs one scan pass.
    ///
    /// Scans up to `pages_to_scan` pages from the cursor position,
    /// checking each against the stable tree, then the unstable tree.
    pub fn scan_pass(&mut self) -> usize {
        let mut scanned = 0;
        let to_scan = self.pages_to_scan.min(self.rmap_pool_count);

        while scanned < to_scan {
            if self.cursor >= self.rmap_pool_count {
                self.cursor = 0;
                self.stats.full_scans += 1;
                // Clear unstable tree on full scan.
                self.clear_unstable();
                if self.rmap_pool_count == 0 {
                    break;
                }
            }

            let item = self.rmap_pool[self.cursor];
            if !item.active {
                self.cursor += 1;
                continue;
            }

            self.stats.pages_scanned += 1;
            scanned += 1;

            // Check stable tree for a match.
            if let Some(stable_idx) = self.search_stable(item.hash) {
                // Merge with existing stable node.
                let rmap = item;
                let _ = self.stable[stable_idx].add_rmap(rmap);
                self.stats.pages_sharing += 1;
                self.stats.merges += 1;
                self.cursor += 1;
                continue;
            }

            // Check unstable tree for a match.
            if let Some(unstable_idx) = self.search_unstable(item.hash) {
                // Found a match — move both to stable tree.
                let partner = self.unstable[unstable_idx];
                self.unstable[unstable_idx].active = false;

                if let Some(sn_idx) = self.alloc_stable_node() {
                    self.stable[sn_idx] = StableNode::new(item.hash, item.pfn);
                    let _ = self.stable[sn_idx].add_rmap(partner.rmap);
                    let _ = self.stable[sn_idx].add_rmap(item);
                    self.stats.pages_shared += 1;
                    self.stats.pages_sharing += 2;
                    self.stats.stable_inserts += 1;
                    self.stats.merges += 1;
                }

                self.cursor += 1;
                continue;
            }

            // No match — add to unstable tree.
            if self.unstable_count < MAX_UNSTABLE_ENTRIES {
                self.unstable[self.unstable_count] = UnstableEntry {
                    hash: item.hash,
                    pfn: item.pfn,
                    rmap: item,
                    active: true,
                };
                self.unstable_count += 1;
                self.stats.unstable_inserts += 1;
            }

            self.stats.pages_unshared += 1;
            self.cursor += 1;
        }

        scanned
    }

    /// Checks if two page data buffers are identical.
    pub fn pages_identical(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        a == b
    }

    /// Hashes page data using FNV-1a.
    fn hash_page(data: &[u8]) -> u64 {
        let mut h = FNV_OFFSET;
        let check_len = data.len().min(PAGE_SIZE);
        for &byte in &data[..check_len] {
            h ^= byte as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        h
    }

    /// Searches the stable tree for a hash.
    fn search_stable(&self, hash: u64) -> Option<usize> {
        for i in 0..MAX_STABLE_NODES {
            if self.stable[i].active && self.stable[i].hash == hash {
                return Some(i);
            }
        }
        None
    }

    /// Searches the unstable tree for a hash.
    fn search_unstable(&self, hash: u64) -> Option<usize> {
        for i in 0..self.unstable_count {
            if self.unstable[i].active && self.unstable[i].hash == hash {
                return Some(i);
            }
        }
        None
    }

    /// Allocates a slot in the stable tree.
    fn alloc_stable_node(&mut self) -> Option<usize> {
        for i in 0..MAX_STABLE_NODES {
            if !self.stable[i].active {
                self.stable_count += 1;
                return Some(i);
            }
        }
        None
    }

    /// Clears the unstable tree (done at the start of each full
    /// scan).
    fn clear_unstable(&mut self) {
        for entry in self.unstable[..self.unstable_count].iter_mut() {
            entry.active = false;
        }
        self.unstable_count = 0;
    }

    /// Returns statistics.
    pub fn stats(&self) -> &KsmScanStats {
        &self.stats
    }

    /// Returns the stable node count.
    pub fn stable_count(&self) -> usize {
        self.stable_count
    }

    /// Returns the unstable entry count.
    pub fn unstable_count(&self) -> usize {
        self.unstable_count
    }

    /// Returns the rmap pool count.
    pub fn rmap_pool_count(&self) -> usize {
        self.rmap_pool_count
    }

    /// Returns the current cursor position.
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
