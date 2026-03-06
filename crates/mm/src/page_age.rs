// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page age tracking for memory reclaim decisions.
//!
//! Tracks page age information to support the multi-generational LRU
//! (MGLRU) algorithm. Each page is assigned to a generation based on
//! recent access patterns; older generations are reclaimed first. This
//! avoids the costly full-list scan of classical LRU by bucketing pages
//! into a small number of generations.
//!
//! # Design
//!
//! ```text
//! Generation 0 (youngest)  ← recently accessed
//! Generation 1
//! Generation 2
//! Generation 3 (oldest)    ← reclaim candidates
//! ```
//!
//! Each generation is a simple counter-based bucket. Pages move from
//! younger to older generations as aggregation ticks pass without an
//! observed access. An access resets the page to generation 0.
//!
//! # Key Types
//!
//! - [`Generation`] — generation identifier (0..MAX_GENERATIONS)
//! - [`PageAgeEntry`] — per-page age metadata
//! - [`PageAgeTracker`] — the tracking engine
//! - [`AgeStats`] — generation distribution statistics
//!
//! Reference: Linux `mm/vmscan.c` (MGLRU / multi-gen LRU).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Number of generations (multi-gen LRU uses 4).
const MAX_GENERATIONS: usize = 4;

/// Maximum number of tracked pages.
const MAX_PAGES: usize = 8192;

/// Ticks before a page ages one generation.
const AGING_INTERVAL: u32 = 4;

// -------------------------------------------------------------------
// Generation
// -------------------------------------------------------------------

/// A generation identifier for the multi-gen LRU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Generation(u8);

impl Generation {
    /// The youngest generation.
    pub const YOUNGEST: Self = Self(0);

    /// The oldest generation.
    pub const OLDEST: Self = Self((MAX_GENERATIONS - 1) as u8);

    /// Creates a new generation value.
    pub const fn new(generation: u8) -> Self {
        Self(generation)
    }

    /// Returns the generation number.
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Returns the next older generation, or `OLDEST` if already there.
    pub const fn age(self) -> Self {
        if (self.0 as usize) < MAX_GENERATIONS - 1 {
            Self(self.0 + 1)
        } else {
            Self::OLDEST
        }
    }

    /// Returns `true` if this is the oldest generation.
    pub const fn is_oldest(self) -> bool {
        self.0 as usize >= MAX_GENERATIONS - 1
    }
}

impl Default for Generation {
    fn default() -> Self {
        Self::YOUNGEST
    }
}

// -------------------------------------------------------------------
// PageAgeEntry
// -------------------------------------------------------------------

/// Per-page age tracking metadata.
#[derive(Debug, Clone, Copy)]
pub struct PageAgeEntry {
    /// Physical frame number.
    pfn: u64,
    /// Current generation.
    generation: Generation,
    /// Ticks since last access.
    ticks_since_access: u32,
    /// Whether the page was accessed in the current window.
    accessed: bool,
    /// Whether this entry is in use.
    in_use: bool,
}

impl PageAgeEntry {
    /// Creates an empty entry.
    pub const fn new() -> Self {
        Self {
            pfn: 0,
            generation: Generation::YOUNGEST,
            ticks_since_access: 0,
            accessed: false,
            in_use: false,
        }
    }

    /// Creates an entry for a specific PFN.
    pub const fn with_pfn(pfn: u64) -> Self {
        Self {
            pfn,
            generation: Generation::YOUNGEST,
            ticks_since_access: 0,
            accessed: false,
            in_use: true,
        }
    }

    /// Returns the PFN.
    pub const fn pfn(&self) -> u64 {
        self.pfn
    }

    /// Returns the current generation.
    pub const fn generation(&self) -> Generation {
        self.generation
    }

    /// Returns ticks since last access.
    pub const fn ticks_since_access(&self) -> u32 {
        self.ticks_since_access
    }

    /// Marks the page as accessed, resetting to youngest generation.
    pub fn mark_accessed(&mut self) {
        self.accessed = true;
        self.generation = Generation::YOUNGEST;
        self.ticks_since_access = 0;
    }

    /// Advances one tick. Ages the page if enough ticks pass.
    pub fn tick(&mut self) {
        if self.accessed {
            self.accessed = false;
            return;
        }
        self.ticks_since_access = self.ticks_since_access.saturating_add(1);
        if self.ticks_since_access >= AGING_INTERVAL {
            self.generation = self.generation.age();
            self.ticks_since_access = 0;
        }
    }
}

impl Default for PageAgeEntry {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// AgeStats
// -------------------------------------------------------------------

/// Distribution of pages across generations.
#[derive(Debug, Clone, Copy)]
pub struct AgeStats {
    /// Count of pages in each generation.
    pub gen_counts: [usize; MAX_GENERATIONS],
    /// Total tracked pages.
    pub total: usize,
}

impl AgeStats {
    /// Creates empty statistics.
    pub const fn new() -> Self {
        Self {
            gen_counts: [0; MAX_GENERATIONS],
            total: 0,
        }
    }

    /// Returns the count for the oldest generation (reclaim candidates).
    pub const fn reclaimable(&self) -> usize {
        self.gen_counts[MAX_GENERATIONS - 1]
    }

    /// Returns the fraction of pages in the oldest generation (0..100).
    pub const fn reclaim_pressure(&self) -> usize {
        if self.total == 0 {
            return 0;
        }
        self.gen_counts[MAX_GENERATIONS - 1] * 100 / self.total
    }
}

impl Default for AgeStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// PageAgeTracker
// -------------------------------------------------------------------

/// Engine tracking page ages for multi-generational LRU reclaim.
pub struct PageAgeTracker {
    /// Per-page entries.
    entries: [PageAgeEntry; MAX_PAGES],
    /// Number of tracked pages.
    count: usize,
    /// Total tick count.
    total_ticks: u64,
}

impl PageAgeTracker {
    /// Creates an empty tracker.
    pub const fn new() -> Self {
        Self {
            entries: [const { PageAgeEntry::new() }; MAX_PAGES],
            count: 0,
            total_ticks: 0,
        }
    }

    /// Returns the number of tracked pages.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Adds a page to be tracked.
    pub fn track(&mut self, pfn: u64) -> Result<()> {
        // Check for duplicate.
        for i in 0..MAX_PAGES {
            if self.entries[i].in_use && self.entries[i].pfn == pfn {
                return Err(Error::AlreadyExists);
            }
        }
        // Find a free slot.
        for i in 0..MAX_PAGES {
            if !self.entries[i].in_use {
                self.entries[i] = PageAgeEntry::with_pfn(pfn);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Stops tracking a page.
    pub fn untrack(&mut self, pfn: u64) -> Result<()> {
        for i in 0..MAX_PAGES {
            if self.entries[i].in_use && self.entries[i].pfn == pfn {
                self.entries[i].in_use = false;
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Records an access for the given PFN.
    pub fn record_access(&mut self, pfn: u64) -> Result<()> {
        for i in 0..MAX_PAGES {
            if self.entries[i].in_use && self.entries[i].pfn == pfn {
                self.entries[i].mark_accessed();
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Advances all tracked pages by one tick.
    pub fn tick_all(&mut self) {
        self.total_ticks = self.total_ticks.saturating_add(1);
        for i in 0..MAX_PAGES {
            if self.entries[i].in_use {
                self.entries[i].tick();
            }
        }
    }

    /// Computes generation distribution statistics.
    pub fn stats(&self) -> AgeStats {
        let mut s = AgeStats::new();
        for i in 0..MAX_PAGES {
            if self.entries[i].in_use {
                let g = self.entries[i].generation.value() as usize;
                if g < MAX_GENERATIONS {
                    s.gen_counts[g] += 1;
                }
                s.total += 1;
            }
        }
        s
    }

    /// Returns PFNs in the oldest generation (reclaim candidates).
    pub fn reclaimable_pfns(&self, out: &mut [u64]) -> usize {
        let mut n = 0;
        for i in 0..MAX_PAGES {
            if n >= out.len() {
                break;
            }
            if self.entries[i].in_use && self.entries[i].generation.is_oldest() {
                out[n] = self.entries[i].pfn;
                n += 1;
            }
        }
        n
    }
}

impl Default for PageAgeTracker {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Creates a new page age tracker.
pub fn create_tracker() -> PageAgeTracker {
    PageAgeTracker::new()
}

/// Advances the tracker by one tick and returns statistics.
pub fn tick_and_stats(tracker: &mut PageAgeTracker) -> AgeStats {
    tracker.tick_all();
    tracker.stats()
}

/// Returns the reclaim pressure percentage (0..100).
pub fn reclaim_pressure(tracker: &PageAgeTracker) -> usize {
    tracker.stats().reclaim_pressure()
}
