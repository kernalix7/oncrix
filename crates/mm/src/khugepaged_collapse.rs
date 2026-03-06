// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! khugepaged THP collapse daemon.
//!
//! Scans process page tables for regions where 512 contiguous
//! base (4 KiB) pages can be collapsed into a single 2 MiB
//! transparent huge page (THP). Operates per-node to respect
//! NUMA locality and provides tunable scan intervals.
//!
//! # Architecture
//!
//! - [`CollapseCandidate`] — a region eligible for collapse
//! - [`NodeScanState`] — per-NUMA-node scan progress
//! - [`CollapseTunables`] — configurable scan parameters
//! - [`CollapseStats`] — counters for monitoring
//! - [`KhugepageCollapser`] — main daemon driving scan and
//!   collapse operations
//!
//! ## Scan algorithm
//!
//! 1. For each NUMA node, walk registered address spaces
//! 2. At each 2 MiB-aligned window, check all 512 PTEs
//! 3. Count present, compatible pages (same node, not pinned,
//!    not shared beyond threshold)
//! 4. If eligible, queue a collapse candidate
//! 5. Process candidates: allocate THP, copy, remap, free
//!    small pages
//!
//! Reference: Linux `mm/khugepaged.c`.

use oncrix_lib::{Error, Result};

// -- Constants

/// Number of base pages per 2 MiB huge page.
const PAGES_PER_HUGE: usize = 512;

/// 2 MiB in bytes.
const HUGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;

/// 2 MiB alignment mask.
const HUGE_ALIGN_MASK: u64 = HUGE_PAGE_SIZE - 1;

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum NUMA nodes for per-node scanning.
const MAX_NODES: usize = 8;

/// Maximum registered address spaces.
const MAX_ADDRESS_SPACES: usize = 128;

/// Maximum collapse candidates queued.
const MAX_CANDIDATES: usize = 64;

/// Default scan sleep interval (ms).
const DEFAULT_SCAN_SLEEP_MS: u64 = 10_000;

/// Default pages to scan per cycle.
const DEFAULT_PAGES_PER_CYCLE: u64 = 4096;

/// Minimum eligible pages for collapse (out of 512).
const MIN_ELIGIBLE_PAGES: u32 = 448;

// -- PageCheckResult

/// Result of checking a single base page for collapse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PageCheckResult {
    /// Page is eligible.
    #[default]
    Eligible,
    /// PTE is not present.
    NotPresent,
    /// Page is pinned.
    Pinned,
    /// Page is on a different NUMA node.
    WrongNode,
    /// Page is shared beyond the allowed threshold.
    TooShared,
}

// -- CollapseCandidate

/// A region identified as eligible for THP collapse.
#[derive(Debug, Clone, Copy)]
pub struct CollapseCandidate {
    /// Address-space ID (process).
    pub as_id: u64,
    /// Base virtual address (2 MiB-aligned).
    pub vaddr: u64,
    /// NUMA node for the target THP.
    pub target_node: u8,
    /// Number of eligible base pages found.
    pub eligible_count: u32,
    /// Number of not-present PTEs.
    pub absent_count: u32,
    /// Whether this candidate is pending.
    pub pending: bool,
    /// Collapse outcome.
    pub collapsed: bool,
}

impl CollapseCandidate {
    const fn empty() -> Self {
        Self {
            as_id: 0,
            vaddr: 0,
            target_node: 0,
            eligible_count: 0,
            absent_count: 0,
            pending: false,
            collapsed: false,
        }
    }
}

impl Default for CollapseCandidate {
    fn default() -> Self {
        Self::empty()
    }
}

// -- AddressSpaceEntry

/// A registered address space for scanning.
#[derive(Debug, Clone, Copy)]
pub struct AddressSpaceEntry {
    /// Address-space (process) identifier.
    pub as_id: u64,
    /// NUMA node affinity.
    pub home_node: u8,
    /// Start of the scannable region.
    pub scan_start: u64,
    /// End of the scannable region.
    pub scan_end: u64,
    /// Current scan cursor.
    pub cursor: u64,
    /// Whether this entry is active.
    pub active: bool,
}

impl AddressSpaceEntry {
    const fn empty() -> Self {
        Self {
            as_id: 0,
            home_node: 0,
            scan_start: 0,
            scan_end: 0,
            cursor: 0,
            active: false,
        }
    }
}

impl Default for AddressSpaceEntry {
    fn default() -> Self {
        Self::empty()
    }
}

// -- NodeScanState

/// Per-NUMA-node scan progress tracking.
#[derive(Debug, Clone, Copy)]
pub struct NodeScanState {
    /// NUMA node ID.
    pub node_id: u8,
    /// Number of address spaces scanned.
    pub spaces_scanned: u64,
    /// Pages scanned on this node.
    pub pages_scanned: u64,
    /// Collapses completed on this node.
    pub collapses: u64,
    /// Whether this node is active.
    pub active: bool,
}

impl NodeScanState {
    const fn empty() -> Self {
        Self {
            node_id: 0,
            spaces_scanned: 0,
            pages_scanned: 0,
            collapses: 0,
            active: false,
        }
    }
}

impl Default for NodeScanState {
    fn default() -> Self {
        Self::empty()
    }
}

// -- CollapseTunables

/// Configurable parameters for the collapser.
#[derive(Debug, Clone, Copy)]
pub struct CollapseTunables {
    /// Scan sleep interval in milliseconds.
    pub scan_sleep_ms: u64,
    /// Pages to scan per cycle.
    pub pages_per_cycle: u64,
    /// Maximum absent PTEs allowed for collapse.
    pub max_ptes_absent: u32,
    /// Maximum shared pages allowed.
    pub max_ptes_shared: u32,
    /// Enable NUMA-aware scanning.
    pub numa_aware: bool,
}

impl CollapseTunables {
    /// Create with default values.
    pub const fn new() -> Self {
        Self {
            scan_sleep_ms: DEFAULT_SCAN_SLEEP_MS,
            pages_per_cycle: DEFAULT_PAGES_PER_CYCLE,
            max_ptes_absent: 64,
            max_ptes_shared: 0,
            numa_aware: true,
        }
    }
}

impl Default for CollapseTunables {
    fn default() -> Self {
        Self::new()
    }
}

// -- CollapseStats

/// Counters for monitoring the collapser.
#[derive(Debug, Clone, Copy, Default)]
pub struct CollapseStats {
    /// Total scan cycles.
    pub scan_cycles: u64,
    /// Total base pages scanned.
    pub pages_scanned: u64,
    /// Collapse candidates found.
    pub candidates_found: u64,
    /// Successful collapses.
    pub collapses_ok: u64,
    /// Failed collapses (alloc failure, race, etc.).
    pub collapses_failed: u64,
    /// THPs produced.
    pub thps_produced: u64,
    /// Small pages freed.
    pub small_pages_freed: u64,
    /// Regions skipped (not eligible).
    pub regions_skipped: u64,
}

// -- KhugepageCollapser

/// khugepaged-style THP collapse daemon.
///
/// Driven cooperatively via `scan_step` calls.
pub struct KhugepageCollapser {
    /// Registered address spaces.
    spaces: [AddressSpaceEntry; MAX_ADDRESS_SPACES],
    /// Number of active address spaces.
    space_count: usize,
    /// Current address-space scan index.
    current_space: usize,
    /// Collapse candidates.
    candidates: [CollapseCandidate; MAX_CANDIDATES],
    /// Number of pending candidates.
    candidate_count: usize,
    /// Per-node scan state.
    node_states: [NodeScanState; MAX_NODES],
    /// Number of active nodes.
    node_count: usize,
    /// Tunables.
    tunables: CollapseTunables,
    /// Statistics.
    stats: CollapseStats,
    /// Whether the daemon is enabled.
    enabled: bool,
    /// Simulated free huge-page pool.
    free_thps: u64,
    /// Pages scanned in the current cycle.
    cycle_pages: u64,
}

impl KhugepageCollapser {
    /// Create a new collapser with default tunables.
    pub const fn new() -> Self {
        Self {
            spaces: [const { AddressSpaceEntry::empty() }; MAX_ADDRESS_SPACES],
            space_count: 0,
            current_space: 0,
            candidates: [const { CollapseCandidate::empty() }; MAX_CANDIDATES],
            candidate_count: 0,
            node_states: [const { NodeScanState::empty() }; MAX_NODES],
            node_count: 0,
            tunables: CollapseTunables::new(),
            stats: CollapseStats {
                scan_cycles: 0,
                pages_scanned: 0,
                candidates_found: 0,
                collapses_ok: 0,
                collapses_failed: 0,
                thps_produced: 0,
                small_pages_freed: 0,
                regions_skipped: 0,
            },
            enabled: false,
            free_thps: 64,
            cycle_pages: 0,
        }
    }

    /// Enable the daemon.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the daemon.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Whether the daemon is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Initialize a NUMA node for scanning.
    pub fn init_node(&mut self, node_id: u8) -> Result<()> {
        if self.node_count >= MAX_NODES {
            return Err(Error::OutOfMemory);
        }
        let idx = (node_id as usize).min(MAX_NODES - 1);
        self.node_states[idx] = NodeScanState {
            node_id,
            spaces_scanned: 0,
            pages_scanned: 0,
            collapses: 0,
            active: true,
        };
        self.node_count += 1;
        Ok(())
    }

    /// Register an address space for scanning.
    pub fn register_space(
        &mut self,
        as_id: u64,
        home_node: u8,
        scan_start: u64,
        scan_end: u64,
    ) -> Result<usize> {
        if scan_start & HUGE_ALIGN_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        if scan_end <= scan_start {
            return Err(Error::InvalidArgument);
        }
        let idx = self
            .spaces
            .iter()
            .position(|s| !s.active)
            .ok_or(Error::OutOfMemory)?;
        self.spaces[idx] = AddressSpaceEntry {
            as_id,
            home_node,
            scan_start,
            scan_end,
            cursor: scan_start,
            active: true,
        };
        self.space_count += 1;
        Ok(idx)
    }

    /// Unregister an address space.
    pub fn unregister_space(&mut self, as_id: u64) -> Result<()> {
        let idx = self
            .spaces
            .iter()
            .position(|s| s.active && s.as_id == as_id)
            .ok_or(Error::NotFound)?;
        self.spaces[idx].active = false;
        self.space_count = self.space_count.saturating_sub(1);
        Ok(())
    }

    /// Update tunables.
    pub fn set_tunables(&mut self, tunables: CollapseTunables) -> Result<()> {
        if tunables.scan_sleep_ms == 0 {
            return Err(Error::InvalidArgument);
        }
        self.tunables = tunables;
        Ok(())
    }

    /// Set the free THP pool count.
    pub fn set_free_thps(&mut self, count: u64) {
        self.free_thps = count;
    }

    /// Perform one scan step.
    ///
    /// Scans the current address space's cursor region, checking
    /// all 512 base pages. If eligible, queues a collapse
    /// candidate. Returns pages scanned.
    pub fn scan_step(&mut self) -> Result<u64> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }
        if self.space_count == 0 {
            return Ok(0);
        }
        // Find next active space.
        let mut found = false;
        let mut search = self.current_space;
        for _ in 0..MAX_ADDRESS_SPACES {
            if self.spaces[search].active {
                found = true;
                break;
            }
            search = (search + 1) % MAX_ADDRESS_SPACES;
        }
        if !found {
            return Ok(0);
        }
        let si = search;
        let cursor = self.spaces[si].cursor & !HUGE_ALIGN_MASK;
        let scan_end = self.spaces[si].scan_end;
        if cursor >= scan_end {
            self.spaces[si].cursor = self.spaces[si].scan_start;
            self.current_space = (si + 1) % MAX_ADDRESS_SPACES;
            return Ok(0);
        }
        // Check 512 pages at cursor.
        let mut eligible = 0u32;
        let mut absent = 0u32;
        let home = self.spaces[si].home_node;
        for i in 0..PAGES_PER_HUGE {
            let check = self.check_page(cursor + (i as u64) * PAGE_SIZE, home);
            match check {
                PageCheckResult::Eligible => eligible += 1,
                PageCheckResult::NotPresent => absent += 1,
                _ => {}
            }
        }
        let scanned = PAGES_PER_HUGE as u64;
        self.stats.pages_scanned += scanned;
        self.cycle_pages += scanned;
        // Update per-node stats.
        let ni = (home as usize).min(MAX_NODES - 1);
        if self.node_states[ni].active {
            self.node_states[ni].pages_scanned += scanned;
            self.node_states[ni].spaces_scanned += 1;
        }
        // Check eligibility.
        if eligible >= MIN_ELIGIBLE_PAGES && absent <= self.tunables.max_ptes_absent {
            self.queue_candidate(self.spaces[si].as_id, cursor, home, eligible, absent)?;
        } else {
            self.stats.regions_skipped += 1;
        }
        // Advance cursor.
        self.spaces[si].cursor = cursor + HUGE_PAGE_SIZE;
        // Cycle bookkeeping.
        if self.cycle_pages >= self.tunables.pages_per_cycle {
            self.cycle_pages = 0;
            self.stats.scan_cycles += 1;
            self.current_space = (si + 1) % MAX_ADDRESS_SPACES;
        }
        Ok(scanned)
    }

    /// Process one pending collapse candidate.
    ///
    /// Performs the allocate-copy-remap sequence. Returns
    /// whether the collapse succeeded.
    pub fn process_collapse(&mut self) -> Result<bool> {
        let idx = {
            let mut found = None;
            for i in 0..MAX_CANDIDATES {
                if self.candidates[i].pending {
                    found = Some(i);
                    break;
                }
            }
            found.ok_or(Error::NotFound)?
        };
        if self.free_thps == 0 {
            self.candidates[idx].pending = false;
            self.candidate_count = self.candidate_count.saturating_sub(1);
            self.stats.collapses_failed += 1;
            return Ok(false);
        }
        self.free_thps -= 1;
        self.candidates[idx].pending = false;
        self.candidates[idx].collapsed = true;
        self.candidate_count = self.candidate_count.saturating_sub(1);
        let node = self.candidates[idx].target_node;
        let ni = (node as usize).min(MAX_NODES - 1);
        if self.node_states[ni].active {
            self.node_states[ni].collapses += 1;
        }
        self.stats.collapses_ok += 1;
        self.stats.thps_produced += 1;
        self.stats.small_pages_freed += PAGES_PER_HUGE as u64;
        Ok(true)
    }

    /// Number of pending candidates.
    pub fn candidate_count(&self) -> usize {
        self.candidate_count
    }

    /// Return statistics.
    pub fn stats(&self) -> &CollapseStats {
        &self.stats
    }

    /// Return tunables.
    pub fn tunables(&self) -> &CollapseTunables {
        &self.tunables
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = CollapseStats::default();
    }

    // -- Internal helpers

    fn check_page(&self, _vaddr: u64, _home_node: u8) -> PageCheckResult {
        // Simulated: all pages eligible.
        PageCheckResult::Eligible
    }

    fn queue_candidate(
        &mut self,
        as_id: u64,
        vaddr: u64,
        node: u8,
        eligible: u32,
        absent: u32,
    ) -> Result<()> {
        let idx = self
            .candidates
            .iter()
            .position(|c| !c.pending && !c.collapsed)
            .ok_or(Error::Busy)?;
        self.candidates[idx] = CollapseCandidate {
            as_id,
            vaddr,
            target_node: node,
            eligible_count: eligible,
            absent_count: absent,
            pending: true,
            collapsed: false,
        };
        self.candidate_count += 1;
        self.stats.candidates_found += 1;
        Ok(())
    }
}

impl Default for KhugepageCollapser {
    fn default() -> Self {
        Self::new()
    }
}
