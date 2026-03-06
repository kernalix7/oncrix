// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Multi-Generation LRU (MGLRU) core.
//!
//! Implements generation-based page aging with multiple tiers, as
//! described in the Linux MGLRU design (CONFIG_LRU_GEN). Pages are
//! assigned to numbered generations; newly referenced pages are
//! promoted to the youngest generation, while unreferenced pages
//! age toward the oldest generation and become candidates for
//! eviction.
//!
//! A per-node bloom filter is maintained for access tracking:
//! when a page is accessed, its address is inserted into the
//! bloom filter for the current generation. During aging, the
//! bloom filter is consulted to decide promotion vs. demotion.
//!
//! # Key Types
//!
//! - [`GenTier`] — tier within a generation (hot / cold)
//! - [`GenPage`] — page descriptor with generation metadata
//! - [`Generation`] — a single generation holding pages
//! - [`NodeGenState`] — per-NUMA-node generation manager
//! - [`BloomFilter`] — simple bloom filter for access tracking
//! - [`LruGenStats`] — aggregate MGLRU statistics
//! - [`LruGenCore`] — top-level MGLRU engine
//!
//! Reference: Linux `mm/vmscan.c` (CONFIG_LRU_GEN,
//! `lru_gen_struct`, `evict_pages`, `age_lruvec`).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of generations per node.
const MAX_GENERATIONS: usize = 8;

/// Maximum pages per generation.
const MAX_PAGES_PER_GEN: usize = 256;

/// Maximum NUMA nodes.
const MAX_NUMA_NODES: usize = 4;

/// Bloom filter bit array size (in u64 words).
const BLOOM_WORDS: usize = 16;

/// Total bits in the bloom filter.
const BLOOM_BITS: usize = BLOOM_WORDS * 64;

/// Number of hash functions for the bloom filter.
const BLOOM_HASHES: usize = 3;

/// Minimum generation number (oldest).
const MIN_GEN: u32 = 0;

// -------------------------------------------------------------------
// GenTier
// -------------------------------------------------------------------

/// Tier within a generation (sub-classification).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GenTier {
    /// Hot tier — recently and frequently accessed.
    #[default]
    Hot,
    /// Cold tier — accessed once or aging toward eviction.
    Cold,
}

// -------------------------------------------------------------------
// GenPage
// -------------------------------------------------------------------

/// A page tracked by the MGLRU subsystem.
#[derive(Debug, Clone, Copy)]
pub struct GenPage {
    /// Physical frame number.
    pub pfn: u64,
    /// Current generation number.
    pub generation_id: u32,
    /// Tier within the generation.
    pub tier: GenTier,
    /// NUMA node this page belongs to.
    pub node_id: u16,
    /// Access count in the current generation.
    pub access_count: u16,
    /// Whether this page is file-backed (vs. anonymous).
    pub file_backed: bool,
    /// Whether this slot is active.
    active: bool,
}

impl GenPage {
    /// Create an empty, inactive page descriptor.
    const fn empty() -> Self {
        Self {
            pfn: 0,
            generation_id: 0,
            tier: GenTier::Hot,
            node_id: 0,
            access_count: 0,
            file_backed: false,
            active: false,
        }
    }

    /// Whether this slot is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }
}

impl Default for GenPage {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// Generation
// -------------------------------------------------------------------

/// A single generation holding a set of pages.
pub struct Generation {
    /// Generation number (0 = oldest).
    pub gen_id: u32,
    /// Pages in this generation.
    pages: [GenPage; MAX_PAGES_PER_GEN],
    /// Number of active pages.
    count: usize,
    /// Number of hot-tier pages.
    hot_count: usize,
    /// Number of cold-tier pages.
    cold_count: usize,
}

impl Generation {
    /// Create an empty generation.
    const fn empty(gen_id: u32) -> Self {
        Self {
            gen_id,
            pages: [GenPage::empty(); MAX_PAGES_PER_GEN],
            count: 0,
            hot_count: 0,
            cold_count: 0,
        }
    }

    /// Number of pages in this generation.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Number of hot-tier pages.
    pub const fn hot_count(&self) -> usize {
        self.hot_count
    }

    /// Number of cold-tier pages.
    pub const fn cold_count(&self) -> usize {
        self.cold_count
    }

    /// Read-only access to pages.
    pub fn pages(&self) -> &[GenPage] {
        &self.pages[..self.count]
    }

    /// Add a page to this generation. Returns error if full.
    fn add_page(&mut self, page: GenPage) -> Result<()> {
        if self.count >= MAX_PAGES_PER_GEN {
            return Err(Error::OutOfMemory);
        }
        let mut pg = page;
        pg.generation_id = self.gen_id;
        pg.active = true;
        self.pages[self.count] = pg;
        self.count += 1;
        match pg.tier {
            GenTier::Hot => self.hot_count += 1,
            GenTier::Cold => self.cold_count += 1,
        }
        Ok(())
    }

    /// Remove a page by PFN. Returns the removed page.
    fn remove_page(&mut self, pfn: u64) -> Result<GenPage> {
        let pos = self.pages[..self.count]
            .iter()
            .position(|p| p.active && p.pfn == pfn)
            .ok_or(Error::NotFound)?;

        let removed = self.pages[pos];
        // Shift remaining pages.
        let last = self.count - 1;
        if pos < last {
            self.pages[pos] = self.pages[last];
        }
        self.pages[last] = GenPage::empty();
        self.count -= 1;
        match removed.tier {
            GenTier::Hot => {
                self.hot_count = self.hot_count.saturating_sub(1);
            }
            GenTier::Cold => {
                self.cold_count = self.cold_count.saturating_sub(1);
            }
        }
        Ok(removed)
    }
}

// -------------------------------------------------------------------
// BloomFilter
// -------------------------------------------------------------------

/// Simple bloom filter for page access tracking.
///
/// When a page is accessed, its PFN is inserted. During aging the
/// filter is consulted to decide promotion vs. demotion.
pub struct BloomFilter {
    /// Bit array stored as u64 words.
    bits: [u64; BLOOM_WORDS],
    /// Number of insertions.
    insertions: u64,
}

impl BloomFilter {
    /// Create a cleared bloom filter.
    const fn new() -> Self {
        Self {
            bits: [0u64; BLOOM_WORDS],
            insertions: 0,
        }
    }

    /// Insert a PFN into the filter.
    pub fn insert(&mut self, pfn: u64) {
        for h in 0..BLOOM_HASHES {
            let bit = Self::hash(pfn, h as u64) % BLOOM_BITS;
            let word = bit / 64;
            let offset = bit % 64;
            self.bits[word] |= 1u64 << offset;
        }
        self.insertions += 1;
    }

    /// Test whether a PFN may have been inserted.
    pub fn may_contain(&self, pfn: u64) -> bool {
        for h in 0..BLOOM_HASHES {
            let bit = Self::hash(pfn, h as u64) % BLOOM_BITS;
            let word = bit / 64;
            let offset = bit % 64;
            if self.bits[word] & (1u64 << offset) == 0 {
                return false;
            }
        }
        true
    }

    /// Reset the filter for a new generation cycle.
    pub fn clear(&mut self) {
        self.bits = [0u64; BLOOM_WORDS];
        self.insertions = 0;
    }

    /// Number of insertions since last clear.
    pub const fn insertions(&self) -> u64 {
        self.insertions
    }

    /// Simple hash: FNV-1a-like mixing.
    fn hash(pfn: u64, seed: u64) -> usize {
        let mut h = 0xcbf2_9ce4_8422_2325u64 ^ seed;
        h ^= pfn;
        h = h.wrapping_mul(0x0100_0000_01b3);
        h ^= h >> 17;
        h as usize
    }
}

// -------------------------------------------------------------------
// NodeGenState
// -------------------------------------------------------------------

/// Per-NUMA-node generation management.
pub struct NodeGenState {
    /// NUMA node identifier.
    pub node_id: u16,
    /// Generations (index 0 = oldest, last = youngest).
    generations: [Generation; MAX_GENERATIONS],
    /// Number of active generations.
    active_gens: usize,
    /// Youngest generation number.
    youngest_gen: u32,
    /// Bloom filter for the current youngest generation.
    bloom: BloomFilter,
    /// Total pages across all generations.
    total_pages: usize,
}

impl NodeGenState {
    /// Create a new per-node state with one initial generation.
    const fn new(node_id: u16) -> Self {
        Self {
            node_id,
            generations: [
                Generation::empty(0),
                Generation::empty(1),
                Generation::empty(2),
                Generation::empty(3),
                Generation::empty(4),
                Generation::empty(5),
                Generation::empty(6),
                Generation::empty(7),
            ],
            active_gens: 1,
            youngest_gen: 0,
            bloom: BloomFilter::new(),
            total_pages: 0,
        }
    }

    /// Total pages managed by this node.
    pub const fn total_pages(&self) -> usize {
        self.total_pages
    }

    /// Current youngest generation number.
    pub const fn youngest_gen(&self) -> u32 {
        self.youngest_gen
    }

    /// Number of active generations.
    pub const fn active_gens(&self) -> usize {
        self.active_gens
    }

    /// Access to the bloom filter.
    pub fn bloom(&self) -> &BloomFilter {
        &self.bloom
    }

    /// Add a page into the youngest generation.
    fn add_page(&mut self, pfn: u64, file_backed: bool) -> Result<()> {
        let idx = self.youngest_gen as usize % MAX_GENERATIONS;
        let page = GenPage {
            pfn,
            generation_id: self.youngest_gen,
            tier: GenTier::Hot,
            node_id: self.node_id,
            access_count: 1,
            file_backed,
            active: true,
        };
        self.generations[idx].add_page(page)?;
        self.bloom.insert(pfn);
        self.total_pages += 1;
        Ok(())
    }

    /// Create a new youngest generation, aging all existing ones.
    fn create_new_generation(&mut self) -> Result<()> {
        if self.active_gens >= MAX_GENERATIONS {
            return Err(Error::OutOfMemory);
        }
        self.youngest_gen += 1;
        let idx = self.youngest_gen as usize % MAX_GENERATIONS;
        self.generations[idx] = Generation::empty(self.youngest_gen);
        self.active_gens += 1;
        self.bloom.clear();
        Ok(())
    }

    /// Evict cold pages from the oldest generation.
    /// Returns the number of pages evicted.
    fn evict_oldest(&mut self, max_evict: usize) -> usize {
        if self.active_gens == 0 {
            return 0;
        }
        let oldest_gen = self
            .youngest_gen
            .saturating_sub(self.active_gens as u32 - 1);
        let idx = oldest_gen as usize % MAX_GENERATIONS;

        let mut evicted = 0;
        // Evict cold-tier pages first, then hot if needed.
        while evicted < max_evict && self.generations[idx].count > 0 {
            let last = self.generations[idx].count - 1;
            let pg = self.generations[idx].pages[last];
            if !pg.active {
                break;
            }
            self.generations[idx].pages[last] = GenPage::empty();
            self.generations[idx].count -= 1;
            match pg.tier {
                GenTier::Hot => {
                    self.generations[idx].hot_count =
                        self.generations[idx].hot_count.saturating_sub(1);
                }
                GenTier::Cold => {
                    self.generations[idx].cold_count =
                        self.generations[idx].cold_count.saturating_sub(1);
                }
            }
            self.total_pages = self.total_pages.saturating_sub(1);
            evicted += 1;
        }

        // If oldest generation is now empty, retire it.
        if self.generations[idx].count == 0 && self.active_gens > 1 {
            self.active_gens -= 1;
        }
        evicted
    }
}

// -------------------------------------------------------------------
// LruGenStats
// -------------------------------------------------------------------

/// Aggregate MGLRU statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct LruGenStats {
    /// Total pages added.
    pub pages_added: u64,
    /// Total pages promoted.
    pub pages_promoted: u64,
    /// Total pages demoted.
    pub pages_demoted: u64,
    /// Total pages evicted from oldest generation.
    pub pages_evicted: u64,
    /// Generations created.
    pub generations_created: u64,
    /// Bloom filter lookups.
    pub bloom_lookups: u64,
    /// Bloom filter hits.
    pub bloom_hits: u64,
    /// Aging sweeps performed.
    pub aging_sweeps: u64,
}

// -------------------------------------------------------------------
// LruGenCore
// -------------------------------------------------------------------

/// Top-level MGLRU engine managing per-node generation states.
pub struct LruGenCore {
    /// Per-NUMA-node generation states.
    nodes: [NodeGenState; MAX_NUMA_NODES],
    /// Number of active NUMA nodes.
    active_nodes: usize,
    /// Aggregate statistics.
    stats: LruGenStats,
}

impl Default for LruGenCore {
    fn default() -> Self {
        Self::new()
    }
}

impl LruGenCore {
    /// Create a new MGLRU engine with one active node.
    pub const fn new() -> Self {
        Self {
            nodes: [
                NodeGenState::new(0),
                NodeGenState::new(1),
                NodeGenState::new(2),
                NodeGenState::new(3),
            ],
            active_nodes: 1,
            stats: LruGenStats {
                pages_added: 0,
                pages_promoted: 0,
                pages_demoted: 0,
                pages_evicted: 0,
                generations_created: 0,
                bloom_lookups: 0,
                bloom_hits: 0,
                aging_sweeps: 0,
            },
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

    /// Current statistics.
    pub const fn stats(&self) -> &LruGenStats {
        &self.stats
    }

    /// Add a new page to the youngest generation on the given node.
    pub fn add_page(&mut self, node_id: u16, pfn: u64, file_backed: bool) -> Result<()> {
        let node = self.get_node_mut(node_id)?;
        node.add_page(pfn, file_backed)?;
        self.stats.pages_added += 1;
        Ok(())
    }

    /// Record a page access (promote if it has aged).
    pub fn record_access(&mut self, node_id: u16, pfn: u64) -> Result<()> {
        let nid = node_id as usize;
        if nid >= self.active_nodes {
            return Err(Error::InvalidArgument);
        }
        self.stats.bloom_lookups += 1;

        let youngest = self.nodes[nid].youngest_gen;

        // Check bloom filter — if present, already young.
        if self.nodes[nid].bloom.may_contain(pfn) {
            self.stats.bloom_hits += 1;
            return Ok(());
        }

        // Search older generations for this page and promote.
        let oldest_gen = youngest.saturating_sub(self.nodes[nid].active_gens as u32 - 1);
        let mut found_gen = None;
        for g in oldest_gen..youngest {
            let idx = g as usize % MAX_GENERATIONS;
            if self.nodes[nid].generations[idx].pages[..self.nodes[nid].generations[idx].count]
                .iter()
                .any(|p| p.active && p.pfn == pfn)
            {
                found_gen = Some(g);
                break;
            }
        }

        if let Some(old_g) = found_gen {
            let old_idx = old_g as usize % MAX_GENERATIONS;
            let page = self.nodes[nid].generations[old_idx].remove_page(pfn)?;
            let young_idx = youngest as usize % MAX_GENERATIONS;
            let mut promoted = page;
            promoted.generation_id = youngest;
            promoted.tier = GenTier::Hot;
            promoted.access_count += 1;
            self.nodes[nid].generations[young_idx].add_page(promoted)?;
            self.nodes[nid].bloom.insert(pfn);
            self.stats.pages_promoted += 1;
        }
        Ok(())
    }

    /// Create a new youngest generation on a node, aging all
    /// existing ones.
    pub fn age_node(&mut self, node_id: u16) -> Result<()> {
        let node = self.get_node_mut(node_id)?;
        node.create_new_generation()?;
        self.stats.generations_created += 1;
        self.stats.aging_sweeps += 1;
        Ok(())
    }

    /// Evict pages from the oldest generation of a node.
    /// Returns the number of pages evicted.
    pub fn evict(&mut self, node_id: u16, max_evict: usize) -> Result<usize> {
        let node = self.get_node_mut(node_id)?;
        let evicted = node.evict_oldest(max_evict);
        self.stats.pages_evicted += evicted as u64;
        Ok(evicted)
    }

    /// Total pages across all active nodes.
    pub fn total_pages(&self) -> usize {
        self.nodes[..self.active_nodes]
            .iter()
            .map(|n| n.total_pages())
            .sum()
    }

    /// Mutable reference to a node by ID.
    fn get_node_mut(&mut self, node_id: u16) -> Result<&mut NodeGenState> {
        let idx = node_id as usize;
        if idx >= self.active_nodes {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.nodes[idx])
    }
}
