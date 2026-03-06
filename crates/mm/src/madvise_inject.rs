// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory advice fault injection for testing.
//!
//! Extends the `madvise` subsystem with fault-injection capabilities
//! for stress-testing memory reclaim, page migration, and CoW paths.
//! An injection rule specifies an address range and an advice type that
//! should fail with a controllable error code at a given probability.
//!
//! # Design
//!
//! ```text
//!  register_injection(range, advice, error, probability)
//!     │
//!     ├─ madvise(addr, len, MADV_DONTNEED)
//!     │   └─ injection matched? → return injected error
//!     └─ normal madvise path
//! ```
//!
//! # Key Types
//!
//! - [`MadviseAdvice`] — POSIX madvise advice values
//! - [`InjectionRule`] — fault injection rule
//! - [`MadviseInjector`] — manages injection rules
//! - [`MadviseInjectStats`] — injection statistics
//!
//! Reference: Linux `mm/madvise.c`, POSIX `madvise(2)`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum injection rules.
const MAX_RULES: usize = 128;

/// Maximum probability value (100 = 100%).
const MAX_PROBABILITY: u32 = 100;

/// Page size.
const PAGE_SIZE: u64 = 4096;

// -------------------------------------------------------------------
// MadviseAdvice
// -------------------------------------------------------------------

/// POSIX madvise advice values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MadviseAdvice {
    /// No special treatment.
    Normal,
    /// Expect random access.
    Random,
    /// Expect sequential access.
    Sequential,
    /// Will need this data soon.
    WillNeed,
    /// Do not need this data.
    DontNeed,
    /// Free the pages (anonymous only).
    Free,
    /// Remove the pages entirely.
    Remove,
    /// Do not fork this range.
    DontFork,
    /// Fork normally.
    DoFork,
    /// Mark for huge-page merging.
    Hugepage,
    /// Unmark for huge-page merging.
    NoHugepage,
    /// Collapse to huge page.
    Collapse,
}

impl MadviseAdvice {
    /// Return a label string.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Normal => "MADV_NORMAL",
            Self::Random => "MADV_RANDOM",
            Self::Sequential => "MADV_SEQUENTIAL",
            Self::WillNeed => "MADV_WILLNEED",
            Self::DontNeed => "MADV_DONTNEED",
            Self::Free => "MADV_FREE",
            Self::Remove => "MADV_REMOVE",
            Self::DontFork => "MADV_DONTFORK",
            Self::DoFork => "MADV_DOFORK",
            Self::Hugepage => "MADV_HUGEPAGE",
            Self::NoHugepage => "MADV_NOHUGEPAGE",
            Self::Collapse => "MADV_COLLAPSE",
        }
    }

    /// Check whether this advice can cause page faults.
    pub const fn can_fault(&self) -> bool {
        matches!(self, Self::DontNeed | Self::Free | Self::Remove)
    }
}

// -------------------------------------------------------------------
// InjectionRule
// -------------------------------------------------------------------

/// Fault injection rule for madvise.
#[derive(Debug, Clone, Copy)]
pub struct InjectionRule {
    /// Start address of the affected range.
    start_addr: u64,
    /// End address of the affected range.
    end_addr: u64,
    /// Advice to intercept.
    advice: MadviseAdvice,
    /// Error to inject.
    error: Error,
    /// Probability (0-100).
    probability: u32,
    /// Whether the rule is enabled.
    enabled: bool,
    /// Number of times this rule fired.
    hit_count: u64,
}

impl InjectionRule {
    /// Create a new injection rule.
    pub const fn new(
        start_addr: u64,
        end_addr: u64,
        advice: MadviseAdvice,
        error: Error,
        probability: u32,
    ) -> Self {
        Self {
            start_addr,
            end_addr,
            advice,
            error,
            probability,
            enabled: true,
            hit_count: 0,
        }
    }

    /// Return the start address.
    pub const fn start_addr(&self) -> u64 {
        self.start_addr
    }

    /// Return the end address.
    pub const fn end_addr(&self) -> u64 {
        self.end_addr
    }

    /// Return the advice.
    pub const fn advice(&self) -> MadviseAdvice {
        self.advice
    }

    /// Return the error to inject.
    pub const fn error(&self) -> Error {
        self.error
    }

    /// Return the probability.
    pub const fn probability(&self) -> u32 {
        self.probability
    }

    /// Check whether the rule is enabled.
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Return the hit count.
    pub const fn hit_count(&self) -> u64 {
        self.hit_count
    }

    /// Enable or disable the rule.
    pub fn set_enabled(&mut self, val: bool) {
        self.enabled = val;
    }

    /// Check whether an address and advice match this rule.
    pub fn matches(&self, addr: u64, advice: MadviseAdvice) -> bool {
        self.enabled
            && self.advice as u8 == advice as u8
            && addr >= self.start_addr
            && addr < self.end_addr
    }

    /// Record a hit.
    pub fn record_hit(&mut self) {
        self.hit_count = self.hit_count.saturating_add(1);
    }

    /// Return the range size in pages.
    pub const fn page_count(&self) -> u64 {
        (self.end_addr - self.start_addr) / PAGE_SIZE
    }
}

impl Default for InjectionRule {
    fn default() -> Self {
        Self {
            start_addr: 0,
            end_addr: 0,
            advice: MadviseAdvice::Normal,
            error: Error::InvalidArgument,
            probability: 0,
            enabled: false,
            hit_count: 0,
        }
    }
}

// -------------------------------------------------------------------
// MadviseInjectStats
// -------------------------------------------------------------------

/// Injection statistics.
#[derive(Debug, Clone, Copy)]
pub struct MadviseInjectStats {
    /// Total madvise calls checked.
    pub total_checks: u64,
    /// Total injections fired.
    pub total_injections: u64,
    /// Rules registered.
    pub rules_registered: u64,
    /// Rules disabled.
    pub rules_disabled: u64,
}

impl MadviseInjectStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            total_checks: 0,
            total_injections: 0,
            rules_registered: 0,
            rules_disabled: 0,
        }
    }

    /// Injection rate as percent.
    pub const fn injection_rate_pct(&self) -> u64 {
        if self.total_checks == 0 {
            return 0;
        }
        self.total_injections * 100 / self.total_checks
    }
}

impl Default for MadviseInjectStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// MadviseInjector
// -------------------------------------------------------------------

/// Manages fault injection rules for madvise.
pub struct MadviseInjector {
    /// Injection rules.
    rules: [InjectionRule; MAX_RULES],
    /// Number of registered rules.
    count: usize,
    /// Statistics.
    stats: MadviseInjectStats,
    /// Global enable flag.
    enabled: bool,
}

impl MadviseInjector {
    /// Create a new injector.
    pub const fn new() -> Self {
        Self {
            rules: [const {
                InjectionRule {
                    start_addr: 0,
                    end_addr: 0,
                    advice: MadviseAdvice::Normal,
                    error: Error::InvalidArgument,
                    probability: 0,
                    enabled: false,
                    hit_count: 0,
                }
            }; MAX_RULES],
            count: 0,
            stats: MadviseInjectStats::new(),
            enabled: false,
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &MadviseInjectStats {
        &self.stats
    }

    /// Return the number of registered rules.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Check whether the injector is globally enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable the injector globally.
    pub fn set_enabled(&mut self, val: bool) {
        self.enabled = val;
    }

    /// Register a new injection rule.
    pub fn register(
        &mut self,
        start_addr: u64,
        end_addr: u64,
        advice: MadviseAdvice,
        error: Error,
        probability: u32,
    ) -> Result<()> {
        if start_addr >= end_addr {
            return Err(Error::InvalidArgument);
        }
        if probability > MAX_PROBABILITY {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_RULES {
            return Err(Error::OutOfMemory);
        }
        self.rules[self.count] =
            InjectionRule::new(start_addr, end_addr, advice, error, probability);
        self.count += 1;
        self.stats.rules_registered += 1;
        Ok(())
    }

    /// Check whether an madvise call should be intercepted.
    pub fn check(&mut self, addr: u64, advice: MadviseAdvice) -> Option<Error> {
        if !self.enabled {
            return None;
        }
        self.stats.total_checks += 1;
        for idx in 0..self.count {
            if self.rules[idx].matches(addr, advice) {
                self.rules[idx].record_hit();
                self.stats.total_injections += 1;
                let err = self.rules[idx].error();
                return Some(err);
            }
        }
        None
    }

    /// Disable a rule by index.
    pub fn disable_rule(&mut self, index: usize) -> Result<()> {
        if index >= self.count {
            return Err(Error::NotFound);
        }
        self.rules[index].set_enabled(false);
        self.stats.rules_disabled += 1;
        Ok(())
    }

    /// Get a rule by index.
    pub fn get_rule(&self, index: usize) -> Option<&InjectionRule> {
        if index < self.count {
            Some(&self.rules[index])
        } else {
            None
        }
    }
}

impl Default for MadviseInjector {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the maximum number of injection rules.
pub const fn max_rules() -> usize {
    MAX_RULES
}

/// Return the maximum probability value.
pub const fn max_probability() -> u32 {
    MAX_PROBABILITY
}
