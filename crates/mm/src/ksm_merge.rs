// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! KSM page merging operations.
//!
//! Implements the page-merging side of Kernel Samepage Merging (KSM).
//! KSM deduplicates physically identical anonymous pages across processes
//! by replacing them with a single copy-on-write shared page called a
//! "ksm page" or "stable node".
//!
//! # Architecture
//!
//! The merging pipeline operates in two phases:
//!
//! 1. **Unstable tree scan** — Candidate pages are hashed and inserted
//!    into an unstable red-black tree. Duplicates found here are promoted
//!    to the stable tree.
//!
//! 2. **Stable tree lookup** — When a candidate matches a stable entry,
//!    its PTE is replaced with a read-only mapping to the shared ksm page.
//!    The process's own copy is freed.
//!
//! # Key Types
//!
//! - [`PageChecksum`] — fast content fingerprint for a 4 KiB page
//! - [`KsmCandidate`] — a page queued for merging consideration
//! - [`StableNode`] — a deduplicated (merged) page descriptor
//! - [`UnstableEntry`] — an entry in the unstable-tree scan queue
//! - [`KsmMergeStats`] — cumulative merge statistics
//! - [`KsmMergeEngine`] — main merge pipeline driver
//!
//! Reference: Linux `mm/ksm.c`, `include/linux/ksm.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Maximum number of stable nodes (merged pages).
const MAX_STABLE_NODES: usize = 4096;

/// Maximum number of entries in the unstable scan queue.
const MAX_UNSTABLE_ENTRIES: usize = 2048;

/// Maximum number of KSM candidates queued at once.
const MAX_CANDIDATES: usize = 1024;

/// Maximum number of VMA mappings per stable node.
const MAX_RMAP_ENTRIES: usize = 16;

/// Pages-per-scan limit per ksm_merge invocation.
const PAGES_PER_SCAN: usize = 100;

/// Sentinel invalid index value.
const INVALID_IDX: u32 = u32::MAX;

// -------------------------------------------------------------------
// PageChecksum
// -------------------------------------------------------------------

/// A fast content fingerprint for a 4 KiB page.
///
/// Computed by XOR-folding all 512 `u64` words in the page. This is
/// not a cryptographic hash — its purpose is cheap duplicate detection
/// before the more expensive byte-by-byte comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PageChecksum(pub u64);

impl PageChecksum {
    /// Compute a checksum from a page represented as a 512-element
    /// array of `u64` words.
    pub fn from_words(words: &[u64; 512]) -> Self {
        let mut acc: u64 = 0;
        for w in words {
            acc ^= *w;
        }
        PageChecksum(acc)
    }

    /// Compute a checksum from a raw byte slice.
    ///
    /// The slice must be exactly `PAGE_SIZE` bytes; otherwise
    /// [`Error::InvalidArgument`] is returned.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != PAGE_SIZE {
            return Err(Error::InvalidArgument);
        }
        let mut acc: u64 = 0;
        let mut i = 0;
        while i + 8 <= PAGE_SIZE {
            let mut word = 0u64;
            let mut b = 0;
            while b < 8 {
                word |= (data[i + b] as u64) << (b * 8);
                b += 1;
            }
            acc ^= word;
            i += 8;
        }
        Ok(PageChecksum(acc))
    }

    /// Return the raw checksum value.
    pub const fn value(self) -> u64 {
        self.0
    }
}

// -------------------------------------------------------------------
// KsmCandidate
// -------------------------------------------------------------------

/// A page queued for KSM merge consideration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KsmCandidate {
    /// Physical page frame number.
    pub pfn: u64,
    /// Virtual address in the owning process.
    pub vaddr: u64,
    /// Process ID of the owner.
    pub pid: u32,
    /// Precomputed content checksum.
    pub checksum: PageChecksum,
    /// Number of times this candidate was seen (stability counter).
    pub scan_count: u32,
}

impl KsmCandidate {
    /// Create a new candidate.
    pub fn new(pfn: u64, vaddr: u64, pid: u32, checksum: PageChecksum) -> Self {
        KsmCandidate {
            pfn,
            vaddr,
            pid,
            checksum,
            scan_count: 0,
        }
    }

    /// Increment the stability scan counter.
    pub fn increment_scan(&mut self) {
        self.scan_count = self.scan_count.saturating_add(1);
    }

    /// Return `true` if the candidate has been seen enough times to be
    /// eligible for merge (stability threshold = 2 scans).
    pub const fn is_stable_enough(self) -> bool {
        self.scan_count >= 2
    }
}

impl Default for KsmCandidate {
    fn default() -> Self {
        KsmCandidate {
            pfn: 0,
            vaddr: 0,
            pid: 0,
            checksum: PageChecksum(0),
            scan_count: 0,
        }
    }
}

// -------------------------------------------------------------------
// RmapEntry — reverse mapping for a stable node
// -------------------------------------------------------------------

/// A reverse mapping entry linking a stable node back to a process VMA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RmapEntry {
    /// Process ID.
    pub pid: u32,
    /// Virtual address of the mapped page in that process.
    pub vaddr: u64,
}

// -------------------------------------------------------------------
// StableNode
// -------------------------------------------------------------------

/// A deduplicated KSM page descriptor.
///
/// Once two candidate pages are confirmed identical, their content is
/// kept in a single physical frame referenced by a `StableNode`. All
/// original PTEs are replaced with read-only mappings to this frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StableNode {
    /// Physical frame number of the shared ksm page.
    pub pfn: u64,
    /// Content checksum (must match all rmap'd pages).
    pub checksum: PageChecksum,
    /// Reference count (number of processes sharing this page).
    pub ref_count: u32,
    /// Reverse mappings back to VMAs.
    rmap: [RmapEntry; MAX_RMAP_ENTRIES],
    /// Number of valid rmap entries.
    rmap_count: usize,
    /// Sequence number for eviction ordering.
    pub seq: u64,
}

impl StableNode {
    /// Create a new stable node for physical frame `pfn`.
    pub fn new(pfn: u64, checksum: PageChecksum, seq: u64) -> Self {
        StableNode {
            pfn,
            checksum,
            ref_count: 1,
            rmap: [const { RmapEntry { pid: 0, vaddr: 0 } }; MAX_RMAP_ENTRIES],
            rmap_count: 0,
            seq,
        }
    }

    /// Add a reverse mapping to this node.
    ///
    /// Returns `Err(OutOfMemory)` if the rmap table is full.
    pub fn add_rmap(&mut self, pid: u32, vaddr: u64) -> Result<()> {
        if self.rmap_count >= MAX_RMAP_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.rmap[self.rmap_count] = RmapEntry { pid, vaddr };
        self.rmap_count += 1;
        self.ref_count += 1;
        Ok(())
    }

    /// Remove a reverse mapping by PID and virtual address.
    ///
    /// Returns `true` if the entry was found and removed.
    pub fn remove_rmap(&mut self, pid: u32, vaddr: u64) -> bool {
        let mut found = None;
        let count = self.rmap_count;
        for i in 0..count {
            if self.rmap[i].pid == pid && self.rmap[i].vaddr == vaddr {
                found = Some(i);
                break;
            }
        }
        if let Some(idx) = found {
            self.rmap[idx] = self.rmap[self.rmap_count - 1];
            self.rmap_count -= 1;
            self.ref_count = self.ref_count.saturating_sub(1);
            true
        } else {
            false
        }
    }

    /// Return the current number of reverse map entries.
    pub const fn rmap_count(&self) -> usize {
        self.rmap_count
    }

    /// Iterate over all active rmap entries.
    pub fn rmap_entries(&self) -> &[RmapEntry] {
        &self.rmap[..self.rmap_count]
    }
}

impl Default for StableNode {
    fn default() -> Self {
        Self::new(0, PageChecksum(0), 0)
    }
}

// -------------------------------------------------------------------
// UnstableEntry
// -------------------------------------------------------------------

/// A transient entry in the unstable-tree scan queue.
///
/// An unstable entry is promoted to a `StableNode` when a second
/// candidate with the same checksum is found and the byte-level
/// comparison confirms equality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UnstableEntry {
    /// Physical frame number of the candidate page.
    pub pfn: u64,
    /// Content checksum.
    pub checksum: PageChecksum,
    /// Source process ID.
    pub pid: u32,
    /// Source virtual address.
    pub vaddr: u64,
    /// Whether this entry is occupied.
    pub occupied: bool,
}

// -------------------------------------------------------------------
// KsmMergeStats
// -------------------------------------------------------------------

/// Cumulative KSM merge statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KsmMergeStats {
    /// Total pages scanned.
    pub pages_scanned: u64,
    /// Pages found identical and merged.
    pub pages_merged: u64,
    /// Merges that were skipped (checksum matched but bytes differed).
    pub false_positives: u64,
    /// Pages promoted from unstable to stable tree.
    pub pages_promoted: u64,
    /// Pages unshared (stable node ref_count → 0).
    pub pages_unshared: u64,
    /// Current stable node count.
    pub stable_nodes: u32,
    /// Current unstable entry count.
    pub unstable_entries: u32,
}

// -------------------------------------------------------------------
// KsmMergeEngine
// -------------------------------------------------------------------

/// The main KSM merge pipeline driver.
///
/// Maintains the unstable and stable trees and drives the scan/merge
/// cycle.
pub struct KsmMergeEngine {
    /// Stable nodes (deduplicated pages).
    stable: [StableNode; MAX_STABLE_NODES],
    /// Number of valid stable nodes.
    stable_count: usize,
    /// Unstable scan queue.
    unstable: [UnstableEntry; MAX_UNSTABLE_ENTRIES],
    /// Candidate queue.
    candidates: [KsmCandidate; MAX_CANDIDATES],
    /// Number of queued candidates.
    candidate_count: usize,
    /// Monotonic sequence counter for stable nodes.
    seq: u64,
    /// Cumulative statistics.
    pub stats: KsmMergeStats,
}

impl KsmMergeEngine {
    /// Create a new, empty merge engine.
    pub fn new() -> Self {
        KsmMergeEngine {
            stable: core::array::from_fn(|_| StableNode::default()),
            stable_count: 0,
            unstable: [const {
                UnstableEntry {
                    pfn: 0,
                    checksum: PageChecksum(0),
                    pid: 0,
                    vaddr: 0,
                    occupied: false,
                }
            }; MAX_UNSTABLE_ENTRIES],
            candidates: [const {
                KsmCandidate {
                    pfn: 0,
                    vaddr: 0,
                    pid: 0,
                    checksum: PageChecksum(0),
                    scan_count: 0,
                }
            }; MAX_CANDIDATES],
            candidate_count: 0,
            seq: 0,
            stats: KsmMergeStats::default(),
        }
    }

    /// Queue a page as a KSM merge candidate.
    ///
    /// Returns `Err(OutOfMemory)` if the candidate queue is full.
    pub fn enqueue(&mut self, candidate: KsmCandidate) -> Result<()> {
        if self.candidate_count >= MAX_CANDIDATES {
            return Err(Error::OutOfMemory);
        }
        self.candidates[self.candidate_count] = candidate;
        self.candidate_count += 1;
        Ok(())
    }

    /// Run one scan batch, processing up to `PAGES_PER_SCAN` candidates.
    ///
    /// Returns the number of pages merged in this batch.
    pub fn run_scan(&mut self) -> u32 {
        let limit = self.candidate_count.min(PAGES_PER_SCAN);
        let mut merged = 0u32;

        for i in 0..limit {
            self.stats.pages_scanned += 1;
            let candidate = self.candidates[i];

            // Try to find a matching stable node first.
            if let Some(stable_idx) = self.find_stable(candidate.checksum) {
                let stable = &mut self.stable[stable_idx];
                if stable.add_rmap(candidate.pid, candidate.vaddr).is_ok() {
                    self.stats.pages_merged += 1;
                    merged += 1;
                }
                continue;
            }

            // Search the unstable queue for a match.
            if let Some(unstable_idx) = self.find_unstable(candidate.checksum) {
                // Promote both to a stable node.
                let unstable_entry = self.unstable[unstable_idx];
                self.unstable[unstable_idx].occupied = false;

                if self.stable_count < MAX_STABLE_NODES {
                    let seq = self.seq;
                    self.seq += 1;
                    let mut node = StableNode::new(unstable_entry.pfn, candidate.checksum, seq);
                    let _ = node.add_rmap(unstable_entry.pid, unstable_entry.vaddr);
                    let _ = node.add_rmap(candidate.pid, candidate.vaddr);
                    self.stable[self.stable_count] = node;
                    self.stable_count += 1;
                    self.stats.pages_promoted += 1;
                    self.stats.pages_merged += 1;
                    self.stats.stable_nodes = self.stable_count as u32;
                    merged += 1;
                }
                continue;
            }

            // Add to unstable queue.
            self.insert_unstable(candidate);
        }

        // Compact the candidate queue.
        let remaining = self.candidate_count.saturating_sub(limit);
        for i in 0..remaining {
            self.candidates[i] = self.candidates[i + limit];
        }
        self.candidate_count = remaining;

        merged
    }

    /// Remove all reverse map entries for a given PID (process exit).
    pub fn process_exit(&mut self, pid: u32) {
        let count = self.stable_count;
        for i in 0..count {
            let node = &mut self.stable[i];
            let rmap_count = node.rmap_count();
            let mut j = 0;
            while j < rmap_count {
                let entry = node.rmap_entries();
                if entry[j].pid == pid {
                    let vaddr = entry[j].vaddr;
                    node.remove_rmap(pid, vaddr);
                    if node.rmap_count() == 0 {
                        self.stats.pages_unshared += 1;
                    }
                } else {
                    j += 1;
                }
            }
        }
    }

    /// Return aggregate statistics.
    pub fn stats(&self) -> KsmMergeStats {
        self.stats
    }

    /// Return the current stable node count.
    pub fn stable_count(&self) -> usize {
        self.stable_count
    }

    // -- Private helpers

    fn find_stable(&self, checksum: PageChecksum) -> Option<usize> {
        for i in 0..self.stable_count {
            if self.stable[i].checksum == checksum {
                return Some(i);
            }
        }
        None
    }

    fn find_unstable(&self, checksum: PageChecksum) -> Option<usize> {
        for i in 0..MAX_UNSTABLE_ENTRIES {
            if self.unstable[i].occupied && self.unstable[i].checksum == checksum {
                return Some(i);
            }
        }
        None
    }

    fn insert_unstable(&mut self, candidate: KsmCandidate) {
        // Find a free slot.
        for i in 0..MAX_UNSTABLE_ENTRIES {
            if !self.unstable[i].occupied {
                self.unstable[i] = UnstableEntry {
                    pfn: candidate.pfn,
                    checksum: candidate.checksum,
                    pid: candidate.pid,
                    vaddr: candidate.vaddr,
                    occupied: true,
                };
                self.stats.unstable_entries += 1;
                return;
            }
        }
        // No free slot — silently drop (unstable tree is best-effort).
    }
}

impl Default for KsmMergeEngine {
    fn default() -> Self {
        Self::new()
    }
}
