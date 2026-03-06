// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel Same-page Merging (KSM).
//!
//! Scans anonymous pages across all processes looking for identical
//! content. When two pages match, one is freed and both mappings
//! point to a single shared copy marked copy-on-write (COW).
//!
//! This is especially beneficial for virtualisation workloads where
//! many VMs run the same guest OS and share large amounts of
//! identical memory.
//!
//! # Algorithm
//!
//! KSM maintains two red-black-tree-like structures:
//!
//! - **Stable tree** — pages already merged and shared.
//! - **Unstable tree** — candidate pages to be checked on the
//!   next pass. Re-built each scan cycle because pages may change.
//!
//! Each scan:
//! 1. Hash the candidate page.
//! 2. Look up in stable tree (exact comparison if hash matches).
//! 3. If found → merge (COW share).
//! 4. If not → insert into unstable tree; if collision there →
//!    merge both into stable tree.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum pages tracked in the stable tree.
const MAX_STABLE_PAGES: usize = 4096;

/// Maximum pages in the unstable tree per cycle.
const MAX_UNSTABLE_PAGES: usize = 4096;

/// Default scan interval in milliseconds.
const DEFAULT_SLEEP_MS: u64 = 20;

/// Default maximum pages to scan per cycle.
const DEFAULT_PAGES_TO_SCAN: u32 = 100;

// ======================================================================
// Types
// ======================================================================

/// State of a KSM-tracked page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KsmPageState {
    /// Page is in the unstable tree (candidate).
    Unstable,
    /// Page is in the stable tree (merged, COW).
    Stable,
    /// Page has been unmerged (write fault broke COW).
    Unmerged,
}

impl Default for KsmPageState {
    fn default() -> Self {
        Self::Unstable
    }
}

/// Entry in the stable or unstable tree.
#[derive(Debug, Clone, Copy)]
pub struct KsmPage {
    /// Physical frame number of the page.
    pub pfn: u64,
    /// Hash of the page contents (for quick comparison).
    pub hash: u64,
    /// Number of mappings sharing this page (stable only).
    pub share_count: u32,
    /// Page state.
    pub state: KsmPageState,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl KsmPage {
    /// Creates an empty KSM page entry.
    pub const fn new() -> Self {
        Self {
            pfn: 0,
            hash: 0,
            share_count: 0,
            state: KsmPageState::Unstable,
            active: false,
        }
    }
}

impl Default for KsmPage {
    fn default() -> Self {
        Self::new()
    }
}

/// Runtime statistics for KSM.
#[derive(Debug, Clone, Copy)]
pub struct KsmStats {
    /// Total pages scanned since KSM was enabled.
    pub pages_scanned: u64,
    /// Pages currently shared (stable tree).
    pub pages_shared: u64,
    /// Total pages saved (shares minus originals).
    pub pages_saved: u64,
    /// Pages unmerged due to COW faults.
    pub pages_unmerged: u64,
    /// Merge attempts that failed (content mismatch after hash).
    pub merge_failures: u64,
    /// Number of full scan cycles completed.
    pub full_scans: u64,
}

impl KsmStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            pages_scanned: 0,
            pages_shared: 0,
            pages_saved: 0,
            pages_unmerged: 0,
            merge_failures: 0,
            full_scans: 0,
        }
    }
}

impl Default for KsmStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration knobs for KSM.
#[derive(Debug, Clone, Copy)]
pub struct KsmConfig {
    /// Whether KSM scanning is enabled.
    pub enabled: bool,
    /// Sleep time between scan cycles (ms).
    pub sleep_ms: u64,
    /// Maximum pages to scan per cycle.
    pub pages_to_scan: u32,
    /// Whether to merge pages across different NUMA nodes.
    pub merge_across_nodes: bool,
}

impl KsmConfig {
    /// Creates a default KSM configuration.
    pub const fn new() -> Self {
        Self {
            enabled: false,
            sleep_ms: DEFAULT_SLEEP_MS,
            pages_to_scan: DEFAULT_PAGES_TO_SCAN,
            merge_across_nodes: true,
        }
    }
}

impl Default for KsmConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// The KSM subsystem state.
pub struct Ksm {
    /// Configuration.
    config: KsmConfig,
    /// Statistics.
    stats: KsmStats,
    /// Stable tree (merged pages).
    stable: [KsmPage; MAX_STABLE_PAGES],
    /// Number of entries in the stable tree.
    nr_stable: usize,
    /// Unstable tree (candidates rebuilt each cycle).
    unstable: [KsmPage; MAX_UNSTABLE_PAGES],
    /// Number of entries in the unstable tree.
    nr_unstable: usize,
}

impl Ksm {
    /// Creates a new KSM instance.
    pub const fn new() -> Self {
        Self {
            config: KsmConfig::new(),
            stats: KsmStats::new(),
            stable: [KsmPage::new(); MAX_STABLE_PAGES],
            nr_stable: 0,
            unstable: [KsmPage::new(); MAX_UNSTABLE_PAGES],
            nr_unstable: 0,
        }
    }

    /// Enables KSM scanning.
    pub fn enable(&mut self) {
        self.config.enabled = true;
    }

    /// Disables KSM scanning.
    pub fn disable(&mut self) {
        self.config.enabled = false;
    }

    /// Updates the scan configuration.
    pub fn set_config(&mut self, config: KsmConfig) -> Result<()> {
        if config.sleep_ms == 0 || config.pages_to_scan == 0 {
            return Err(Error::InvalidArgument);
        }
        self.config = config;
        Ok(())
    }

    /// Looks up a page by hash in the stable tree.
    pub fn find_stable(&self, hash: u64) -> Option<usize> {
        self.stable[..self.nr_stable]
            .iter()
            .position(|p| p.active && p.hash == hash)
    }

    /// Looks up a page by hash in the unstable tree.
    pub fn find_unstable(&self, hash: u64) -> Option<usize> {
        self.unstable[..self.nr_unstable]
            .iter()
            .position(|p| p.active && p.hash == hash)
    }

    /// Inserts a page into the unstable tree for the current cycle.
    pub fn insert_unstable(&mut self, pfn: u64, hash: u64) -> Result<usize> {
        if self.nr_unstable >= MAX_UNSTABLE_PAGES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.nr_unstable;
        self.unstable[idx] = KsmPage {
            pfn,
            hash,
            share_count: 0,
            state: KsmPageState::Unstable,
            active: true,
        };
        self.nr_unstable += 1;
        Ok(idx)
    }

    /// Promotes two pages to the stable tree (merge).
    ///
    /// `pfn_keep` is the physical frame that survives; `pfn_discard`
    /// is freed and its mappings redirected.
    pub fn merge_to_stable(&mut self, pfn_keep: u64, hash: u64) -> Result<usize> {
        if self.nr_stable >= MAX_STABLE_PAGES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.nr_stable;
        self.stable[idx] = KsmPage {
            pfn: pfn_keep,
            hash,
            share_count: 2,
            state: KsmPageState::Stable,
            active: true,
        };
        self.nr_stable += 1;
        self.stats.pages_shared += 1;
        self.stats.pages_saved += 1;
        Ok(idx)
    }

    /// Adds a new sharer to an existing stable page.
    pub fn add_sharer(&mut self, stable_idx: usize) -> Result<()> {
        if stable_idx >= self.nr_stable {
            return Err(Error::InvalidArgument);
        }
        if !self.stable[stable_idx].active {
            return Err(Error::NotFound);
        }
        self.stable[stable_idx].share_count += 1;
        self.stats.pages_saved += 1;
        Ok(())
    }

    /// Handles a COW break on a stable page.
    pub fn unmerge(&mut self, stable_idx: usize) -> Result<()> {
        if stable_idx >= self.nr_stable {
            return Err(Error::InvalidArgument);
        }
        let page = &mut self.stable[stable_idx];
        if !page.active {
            return Err(Error::NotFound);
        }
        page.share_count = page.share_count.saturating_sub(1);
        self.stats.pages_saved = self.stats.pages_saved.saturating_sub(1);
        self.stats.pages_unmerged += 1;

        if page.share_count <= 1 {
            page.active = false;
            page.state = KsmPageState::Unmerged;
            self.stats.pages_shared = self.stats.pages_shared.saturating_sub(1);
        }
        Ok(())
    }

    /// Clears the unstable tree at the start of a new cycle.
    pub fn reset_unstable(&mut self) {
        for entry in &mut self.unstable[..self.nr_unstable] {
            entry.active = false;
        }
        self.nr_unstable = 0;
        self.stats.full_scans += 1;
    }

    /// Returns a reference to KSM statistics.
    pub fn stats(&self) -> &KsmStats {
        &self.stats
    }

    /// Returns a reference to the current configuration.
    pub fn config(&self) -> &KsmConfig {
        &self.config
    }

    /// Returns the number of stable pages.
    pub fn nr_stable(&self) -> usize {
        self.nr_stable
    }

    /// Returns the number of unstable pages.
    pub fn nr_unstable(&self) -> usize {
        self.nr_unstable
    }
}

impl Default for Ksm {
    fn default() -> Self {
        Self::new()
    }
}
