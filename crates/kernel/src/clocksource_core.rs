// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Clocksource core — kernel timekeeping clock abstraction.
//!
//! Provides a registry of hardware clock sources (TSC, HPET, ACPI PM
//! timer, etc.) and selects the best available source for kernel
//! timekeeping. Each clocksource is rated by quality and the kernel
//! automatically switches to the highest-rated stable source.
//!
//! # Architecture
//!
//! ```text
//! ClockSourceManager
//!  ├── sources[MAX_CLOCKSOURCES]
//!  │    ├── name, rating, mask, mult, shift
//!  │    ├── flags: ClockSourceFlags
//!  │    └── state: CsState
//!  ├── current_source: Option<usize>
//!  └── stats: CsStats
//! ```
//!
//! # Reference
//!
//! Linux `kernel/time/clocksource.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum registered clock sources.
const MAX_CLOCKSOURCES: usize = 16;

/// Maximum name length.
const MAX_NAME_LEN: usize = 32;

// ══════════════════════════════════════════════════════════════
// CsState — clocksource state
// ══════════════════════════════════════════════════════════════

/// Lifecycle state of a clocksource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CsState {
    /// Slot is empty.
    Empty = 0,
    /// Registered but not yet validated.
    Registered = 1,
    /// Validated and available for selection.
    Available = 2,
    /// Currently the active timekeeping source.
    Current = 3,
    /// Marked as unstable (watchdog detected drift).
    Unstable = 4,
}

// ══════════════════════════════════════════════════════════════
// ClockSourceFlags
// ══════════════════════════════════════════════════════════════

/// Capability flags for a clocksource.
#[derive(Debug, Clone, Copy)]
pub struct ClockSourceFlags {
    /// Source is continuous (does not stop in suspend).
    pub continuous: bool,
    /// Source can be used for watchdog verification.
    pub valid_for_watchdog: bool,
    /// Source is per-CPU (not globally coherent).
    pub per_cpu: bool,
    /// Source supports high resolution.
    pub high_res: bool,
}

impl ClockSourceFlags {
    /// Default flags.
    const fn default_flags() -> Self {
        Self {
            continuous: false,
            valid_for_watchdog: false,
            per_cpu: false,
            high_res: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// ClockSourceEntry
// ══════════════════════════════════════════════════════════════

/// A registered clocksource.
#[derive(Clone, Copy)]
pub struct ClockSourceEntry {
    /// Human-readable name (zero-padded).
    pub name: [u8; MAX_NAME_LEN],
    /// Name length.
    pub name_len: usize,
    /// Quality rating (higher is better; 0-400 typical).
    pub rating: u32,
    /// Bitmask for the counter (e.g., 0xFFFF_FFFF for 32-bit).
    pub mask: u64,
    /// Multiplication factor for cycles → nanoseconds.
    pub mult: u32,
    /// Shift factor for cycles → nanoseconds.
    pub shift: u32,
    /// Maximum idle time in nanoseconds before skew risk.
    pub max_idle_ns: u64,
    /// Capability flags.
    pub flags: ClockSourceFlags,
    /// Current state.
    pub state: CsState,
    /// Total reads from this source.
    pub read_count: u64,
}

impl ClockSourceEntry {
    /// Create an empty entry.
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            rating: 0,
            mask: 0,
            mult: 0,
            shift: 0,
            max_idle_ns: 0,
            flags: ClockSourceFlags::default_flags(),
            state: CsState::Empty,
            read_count: 0,
        }
    }

    /// Returns `true` if the slot is occupied.
    pub const fn is_registered(&self) -> bool {
        !matches!(self.state, CsState::Empty)
    }
}

// ══════════════════════════════════════════════════════════════
// CsStats
// ══════════════════════════════════════════════════════════════

/// Clocksource subsystem statistics.
#[derive(Debug, Clone, Copy)]
pub struct CsStats {
    /// Total clocksources registered.
    pub total_registered: u64,
    /// Total clocksources marked unstable.
    pub total_unstable: u64,
    /// Total source switches.
    pub total_switches: u64,
}

impl CsStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            total_registered: 0,
            total_unstable: 0,
            total_switches: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// ClockSourceManager
// ══════════════════════════════════════════════════════════════

/// Manages kernel clocksource registration and selection.
pub struct ClockSourceManager {
    /// Registered clocksources.
    sources: [ClockSourceEntry; MAX_CLOCKSOURCES],
    /// Index of the currently active source (if any).
    current_idx: Option<usize>,
    /// Statistics.
    stats: CsStats,
}

impl ClockSourceManager {
    /// Create a new clocksource manager.
    pub const fn new() -> Self {
        Self {
            sources: [const { ClockSourceEntry::empty() }; MAX_CLOCKSOURCES],
            current_idx: None,
            stats: CsStats::new(),
        }
    }

    /// Register a new clocksource.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if no free slots.
    /// - `InvalidArgument` if name is empty or too long.
    pub fn register(
        &mut self,
        name: &[u8],
        rating: u32,
        mask: u64,
        mult: u32,
        shift: u32,
        flags: ClockSourceFlags,
    ) -> Result<usize> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let slot = self
            .sources
            .iter()
            .position(|s| !s.is_registered())
            .ok_or(Error::OutOfMemory)?;
        let mut entry = ClockSourceEntry::empty();
        entry.name[..name.len()].copy_from_slice(name);
        entry.name_len = name.len();
        entry.rating = rating;
        entry.mask = mask;
        entry.mult = mult;
        entry.shift = shift;
        entry.flags = flags;
        entry.state = CsState::Registered;
        self.sources[slot] = entry;
        self.stats.total_registered += 1;
        // Auto-select if this is the best available.
        self.select_best();
        Ok(slot)
    }

    /// Mark a clocksource as unstable (watchdog detected drift).
    pub fn mark_unstable(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_CLOCKSOURCES {
            return Err(Error::InvalidArgument);
        }
        if !self.sources[slot].is_registered() {
            return Err(Error::NotFound);
        }
        self.sources[slot].state = CsState::Unstable;
        self.stats.total_unstable += 1;
        if self.current_idx == Some(slot) {
            self.current_idx = None;
            self.select_best();
        }
        Ok(())
    }

    /// Return the index of the current clocksource.
    pub fn current(&self) -> Option<usize> {
        self.current_idx
    }

    /// Return a clocksource entry by index.
    pub fn get(&self, slot: usize) -> Result<&ClockSourceEntry> {
        if slot >= MAX_CLOCKSOURCES {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.sources[slot])
    }

    /// Return statistics.
    pub fn stats(&self) -> CsStats {
        self.stats
    }

    // ── Internal ─────────────────────────────────────────────

    /// Select the highest-rated non-unstable source.
    fn select_best(&mut self) {
        let mut best_idx: Option<usize> = None;
        let mut best_rating = 0u32;
        for (i, src) in self.sources.iter().enumerate() {
            if matches!(
                src.state,
                CsState::Registered | CsState::Available | CsState::Current
            ) && src.rating > best_rating
            {
                best_rating = src.rating;
                best_idx = Some(i);
            }
        }
        // Demote old current.
        if let Some(old) = self.current_idx {
            if best_idx != Some(old) {
                if matches!(self.sources[old].state, CsState::Current) {
                    self.sources[old].state = CsState::Available;
                }
                self.stats.total_switches += 1;
            }
        }
        if let Some(idx) = best_idx {
            self.sources[idx].state = CsState::Current;
            self.current_idx = Some(idx);
        }
    }
}
