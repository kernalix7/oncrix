// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page counter abstraction for memory accounting.
//!
//! A hierarchical counter that tracks page usage for memory cgroups.
//! Each counter maintains a current value, a limit, and a parent
//! pointer so charges propagate up the cgroup hierarchy.
//!
//! # Design
//!
//! ```text
//!  PageCounter (root, limit=16 GiB)
//!      ├─ PageCounter (cgroup A, limit=4 GiB)
//!      │     ├─ charge(512 pages)  → updates self + root
//!      │     └─ uncharge(256 pages)
//!      └─ PageCounter (cgroup B, limit=8 GiB)
//! ```
//!
//! # Key Types
//!
//! - [`PageCounter`] — single-level counter with limit
//! - [`PageCounterChain`] — hierarchical counter chain
//! - [`ChargeResult`] — outcome of a charge attempt
//!
//! Reference: Linux `include/linux/page_counter.h`, `mm/page_counter.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum hierarchy depth.
const MAX_DEPTH: usize = 16;

/// Unlimited marker.
pub const PAGE_COUNTER_MAX: u64 = u64::MAX;

// -------------------------------------------------------------------
// PageCounter
// -------------------------------------------------------------------

/// A single page counter with an optional limit.
#[derive(Debug, Clone, Copy)]
pub struct PageCounter {
    /// Current page usage.
    usage: u64,
    /// Maximum observed usage (watermark).
    max_usage: u64,
    /// Configured limit (PAGE_COUNTER_MAX = unlimited).
    limit: u64,
    /// Lowest limit in the ancestor chain.
    effective_limit: u64,
    /// Number of times a charge was denied.
    failcnt: u64,
}

impl PageCounter {
    /// Create a new counter with the given limit.
    pub const fn new(limit: u64) -> Self {
        Self {
            usage: 0,
            max_usage: 0,
            limit,
            effective_limit: limit,
            failcnt: 0,
        }
    }

    /// Create an unlimited counter.
    pub const fn unlimited() -> Self {
        Self::new(PAGE_COUNTER_MAX)
    }

    /// Return current usage.
    pub const fn usage(&self) -> u64 {
        self.usage
    }

    /// Return the limit.
    pub const fn limit(&self) -> u64 {
        self.limit
    }

    /// Return the effective (hierarchical) limit.
    pub const fn effective_limit(&self) -> u64 {
        self.effective_limit
    }

    /// Return peak usage.
    pub const fn max_usage(&self) -> u64 {
        self.max_usage
    }

    /// Return the failure count.
    pub const fn failcnt(&self) -> u64 {
        self.failcnt
    }

    /// Set a new limit.
    pub fn set_limit(&mut self, limit: u64) {
        self.limit = limit;
        if self.effective_limit > limit {
            self.effective_limit = limit;
        }
    }

    /// Update the effective limit from a parent constraint.
    pub fn set_effective_limit(&mut self, parent_limit: u64) {
        self.effective_limit = if parent_limit < self.limit {
            parent_limit
        } else {
            self.limit
        };
    }

    /// Try to charge `nr_pages` against this counter.
    pub fn try_charge(&mut self, nr_pages: u64) -> Result<()> {
        let new_usage = self.usage.saturating_add(nr_pages);
        if new_usage > self.effective_limit {
            self.failcnt += 1;
            return Err(Error::OutOfMemory);
        }
        self.usage = new_usage;
        if self.usage > self.max_usage {
            self.max_usage = self.usage;
        }
        Ok(())
    }

    /// Uncharge `nr_pages` from this counter.
    pub fn uncharge(&mut self, nr_pages: u64) {
        self.usage = self.usage.saturating_sub(nr_pages);
    }

    /// Reset the peak watermark to the current usage.
    pub fn reset_max(&mut self) {
        self.max_usage = self.usage;
    }

    /// Reset the failure counter.
    pub fn reset_failcnt(&mut self) {
        self.failcnt = 0;
    }

    /// Return remaining capacity before the limit.
    pub const fn headroom(&self) -> u64 {
        if self.usage >= self.effective_limit {
            0
        } else {
            self.effective_limit - self.usage
        }
    }
}

impl Default for PageCounter {
    fn default() -> Self {
        Self::unlimited()
    }
}

// -------------------------------------------------------------------
// ChargeResult
// -------------------------------------------------------------------

/// Outcome of a hierarchical charge attempt.
#[derive(Debug, Clone, Copy)]
pub struct ChargeResult {
    /// Whether the charge succeeded.
    pub success: bool,
    /// Index of the counter that denied the charge (if any).
    pub fail_at: Option<usize>,
    /// Remaining headroom at the tightest counter.
    pub min_headroom: u64,
}

impl ChargeResult {
    /// Create a success result.
    pub const fn ok(min_headroom: u64) -> Self {
        Self {
            success: true,
            fail_at: None,
            min_headroom,
        }
    }

    /// Create a failure result.
    pub const fn fail(at: usize) -> Self {
        Self {
            success: false,
            fail_at: Some(at),
            min_headroom: 0,
        }
    }
}

// -------------------------------------------------------------------
// PageCounterChain
// -------------------------------------------------------------------

/// Hierarchical page counter chain (child → root).
pub struct PageCounterChain {
    /// Counters in the chain, index 0 = leaf, last = root.
    counters: [PageCounter; MAX_DEPTH],
    /// Number of valid counters.
    depth: usize,
}

impl PageCounterChain {
    /// Create a new chain with one root counter.
    pub const fn new(root_limit: u64) -> Self {
        let mut counters = [const { PageCounter::unlimited() }; MAX_DEPTH];
        counters[0] = PageCounter::new(root_limit);
        Self { counters, depth: 1 }
    }

    /// Push a child counter onto the chain.
    pub fn push(&mut self, limit: u64) -> Result<()> {
        if self.depth >= MAX_DEPTH {
            return Err(Error::OutOfMemory);
        }
        let mut child = PageCounter::new(limit);
        // Effective limit is min(own, parent).
        if self.depth > 0 {
            let parent_eff = self.counters[self.depth - 1].effective_limit();
            child.set_effective_limit(parent_eff);
        }
        self.counters[self.depth] = child;
        self.depth += 1;
        Ok(())
    }

    /// Return the chain depth.
    pub const fn depth(&self) -> usize {
        self.depth
    }

    /// Try to charge `nr_pages` against all counters in the chain.
    pub fn try_charge(&mut self, nr_pages: u64) -> ChargeResult {
        let mut min_headroom = u64::MAX;

        // Charge from leaf to root.
        for idx in (0..self.depth).rev() {
            if self.counters[idx].try_charge(nr_pages).is_err() {
                // Roll back already-charged ancestors.
                for undo in (idx + 1)..self.depth {
                    self.counters[undo].uncharge(nr_pages);
                }
                return ChargeResult::fail(idx);
            }
            let hr = self.counters[idx].headroom();
            if hr < min_headroom {
                min_headroom = hr;
            }
        }

        ChargeResult::ok(min_headroom)
    }

    /// Uncharge `nr_pages` from all counters.
    pub fn uncharge(&mut self, nr_pages: u64) {
        for idx in 0..self.depth {
            self.counters[idx].uncharge(nr_pages);
        }
    }

    /// Return the tightest headroom across the chain.
    pub fn min_headroom(&self) -> u64 {
        let mut min = u64::MAX;
        for idx in 0..self.depth {
            let hr = self.counters[idx].headroom();
            if hr < min {
                min = hr;
            }
        }
        min
    }
}

impl Default for PageCounterChain {
    fn default() -> Self {
        Self::new(PAGE_COUNTER_MAX)
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Create a two-level counter chain (parent + child).
pub fn create_two_level(parent_limit: u64, child_limit: u64) -> Result<PageCounterChain> {
    let mut chain = PageCounterChain::new(parent_limit);
    chain.push(child_limit)?;
    Ok(chain)
}

/// Charge pages against a chain, returning headroom on success.
pub fn charge_pages(chain: &mut PageCounterChain, nr_pages: u64) -> Result<u64> {
    let result = chain.try_charge(nr_pages);
    if result.success {
        Ok(result.min_headroom)
    } else {
        Err(Error::OutOfMemory)
    }
}

/// Return the usage of the leaf counter in a chain.
pub fn leaf_usage(chain: &PageCounterChain) -> u64 {
    if chain.depth() == 0 {
        return 0;
    }
    chain.counters[chain.depth() - 1].usage()
}
