// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Saturating reference counting (refcount_t).
//!
//! Provides a reference counter that saturates instead of wrapping
//! on overflow, preventing use-after-free and double-free bugs.
//! Unlike plain atomic counters, a refcount_t will stick at
//! `REFCOUNT_SATURATED` on overflow and warn on illegal transitions
//! (increment from 0, decrement below 0).
//!
//! # State Machine
//!
//! ```text
//!   0 (freed) ←── dec_and_test returns true
//!       │
//!       │ (init or inc from valid)
//!       ▼
//!   1..REFCOUNT_MAX (valid range)
//!       │
//!       │ (overflow)
//!       ▼
//!   REFCOUNT_SATURATED (stuck — leaked but safe)
//! ```
//!
//! # Reference
//!
//! Linux `include/linux/refcount.h`, `lib/refcount.c`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum valid reference count before saturation.
const REFCOUNT_MAX: u32 = u32::MAX / 2;

/// Saturated value — the refcount is permanently stuck here.
const REFCOUNT_SATURATED: u32 = u32::MAX;

/// Maximum number of managed refcounts (for the tracker).
const MAX_REFCOUNTS: usize = 512;

// ======================================================================
// Refcount error type
// ======================================================================

/// Refcount operation warnings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefcountWarn {
    /// Attempt to increment a zero refcount (use-after-free).
    IncrementZero,
    /// Attempt to decrement below zero (double-free).
    DecrementBelowZero,
    /// Refcount saturated (leaked object).
    Saturated,
    /// Attempt to operate on an already-saturated refcount.
    AlreadySaturated,
}

// ======================================================================
// Refcount
// ======================================================================

/// A saturating reference counter.
#[derive(Debug, Clone, Copy)]
pub struct Refcount {
    /// Inner value.
    value: u32,
}

impl Refcount {
    /// Creates a new refcount with initial value 1.
    pub const fn new() -> Self {
        Self { value: 1 }
    }

    /// Creates a refcount with a specific initial value.
    pub const fn new_with(value: u32) -> Self {
        Self { value }
    }

    /// Creates a zero refcount (typically for static init).
    pub const fn zero() -> Self {
        Self { value: 0 }
    }

    /// Returns the current value.
    pub fn read(&self) -> u32 {
        self.value
    }

    /// Returns whether the refcount is zero.
    pub fn is_zero(&self) -> bool {
        self.value == 0
    }

    /// Returns whether the refcount has saturated.
    pub fn is_saturated(&self) -> bool {
        self.value == REFCOUNT_SATURATED
    }

    /// Sets the refcount to a specific value (unsafe init).
    pub fn set(&mut self, val: u32) {
        self.value = val;
    }

    /// Initializes the refcount to 1.
    pub fn init(&mut self) {
        self.value = 1;
    }

    /// Increments the refcount by 1.
    ///
    /// Returns a warning if the refcount was zero or saturated.
    pub fn inc(&mut self) -> Option<RefcountWarn> {
        if self.value == 0 {
            // Increment from zero — use-after-free pattern.
            return Some(RefcountWarn::IncrementZero);
        }
        if self.value >= REFCOUNT_SATURATED {
            return Some(RefcountWarn::AlreadySaturated);
        }
        if self.value >= REFCOUNT_MAX {
            self.value = REFCOUNT_SATURATED;
            return Some(RefcountWarn::Saturated);
        }
        self.value += 1;
        None
    }

    /// Increments the refcount by N.
    pub fn inc_by(&mut self, n: u32) -> Option<RefcountWarn> {
        if self.value == 0 {
            return Some(RefcountWarn::IncrementZero);
        }
        if self.value >= REFCOUNT_SATURATED {
            return Some(RefcountWarn::AlreadySaturated);
        }
        let new_val = self.value as u64 + n as u64;
        if new_val > REFCOUNT_MAX as u64 {
            self.value = REFCOUNT_SATURATED;
            return Some(RefcountWarn::Saturated);
        }
        self.value = new_val as u32;
        None
    }

    /// Increments the refcount, but only if it is not zero.
    ///
    /// Returns true if the increment succeeded, false if refcount
    /// was zero.
    pub fn inc_not_zero(&mut self) -> bool {
        if self.value == 0 {
            return false;
        }
        if self.value >= REFCOUNT_SATURATED {
            return true; // Already saturated, no-op but "success".
        }
        if self.value >= REFCOUNT_MAX {
            self.value = REFCOUNT_SATURATED;
            return true;
        }
        self.value += 1;
        true
    }

    /// Decrements the refcount by 1.
    ///
    /// Returns a warning if the decrement went below zero.
    pub fn dec(&mut self) -> Option<RefcountWarn> {
        if self.value == REFCOUNT_SATURATED {
            return Some(RefcountWarn::AlreadySaturated);
        }
        if self.value == 0 {
            return Some(RefcountWarn::DecrementBelowZero);
        }
        self.value -= 1;
        None
    }

    /// Decrements and tests if the refcount reached zero.
    ///
    /// Returns `Ok(true)` if the refcount reached zero (object
    /// should be freed), `Ok(false)` if still positive, or
    /// an error for invalid operations.
    pub fn dec_and_test(&mut self) -> Result<bool> {
        if self.value == REFCOUNT_SATURATED {
            return Err(Error::Busy);
        }
        if self.value == 0 {
            return Err(Error::InvalidArgument);
        }
        self.value -= 1;
        Ok(self.value == 0)
    }

    /// Decrements by N and tests if zero.
    pub fn sub_and_test(&mut self, n: u32) -> Result<bool> {
        if self.value == REFCOUNT_SATURATED {
            return Err(Error::Busy);
        }
        if (self.value as u64) < n as u64 {
            return Err(Error::InvalidArgument);
        }
        self.value -= n;
        Ok(self.value == 0)
    }
}

// ======================================================================
// Refcount statistics
// ======================================================================

/// Statistics for refcount operations (debugging).
#[derive(Debug, Clone, Copy)]
pub struct RefcountStats {
    /// Number of increments.
    inc_count: u64,
    /// Number of decrements.
    dec_count: u64,
    /// Number of saturation events.
    saturations: u64,
    /// Number of increment-from-zero warnings.
    inc_zero_warns: u64,
    /// Number of decrement-below-zero warnings.
    dec_below_zero_warns: u64,
}

impl RefcountStats {
    /// Creates zeroed stats.
    pub const fn new() -> Self {
        Self {
            inc_count: 0,
            dec_count: 0,
            saturations: 0,
            inc_zero_warns: 0,
            dec_below_zero_warns: 0,
        }
    }

    /// Returns the increment count.
    pub fn inc_count(&self) -> u64 {
        self.inc_count
    }

    /// Returns the decrement count.
    pub fn dec_count(&self) -> u64 {
        self.dec_count
    }

    /// Returns the saturation count.
    pub fn saturations(&self) -> u64 {
        self.saturations
    }

    /// Records an increment operation.
    pub fn record_inc(&mut self, warn: Option<RefcountWarn>) {
        self.inc_count = self.inc_count.saturating_add(1);
        match warn {
            Some(RefcountWarn::IncrementZero) => {
                self.inc_zero_warns = self.inc_zero_warns.saturating_add(1);
            }
            Some(RefcountWarn::Saturated) => {
                self.saturations = self.saturations.saturating_add(1);
            }
            _ => {}
        }
    }

    /// Records a decrement operation.
    pub fn record_dec(&mut self, warn: Option<RefcountWarn>) {
        self.dec_count = self.dec_count.saturating_add(1);
        if let Some(RefcountWarn::DecrementBelowZero) = warn {
            self.dec_below_zero_warns = self.dec_below_zero_warns.saturating_add(1);
        }
    }
}

// ======================================================================
// Tracked refcount entry
// ======================================================================

/// A tracked refcount with metadata.
#[derive(Debug, Clone, Copy)]
pub struct TrackedRefcount {
    /// The refcount.
    rc: Refcount,
    /// Object identifier.
    object_id: u64,
    /// Whether this entry is active.
    active: bool,
    /// Creation timestamp (ns).
    created_ns: u64,
    /// Number of inc/dec operations.
    ops_count: u32,
}

impl TrackedRefcount {
    /// Creates an empty tracked refcount.
    pub const fn new() -> Self {
        Self {
            rc: Refcount::zero(),
            object_id: 0,
            active: false,
            created_ns: 0,
            ops_count: 0,
        }
    }

    /// Returns the refcount value.
    pub fn value(&self) -> u32 {
        self.rc.read()
    }

    /// Returns the object ID.
    pub fn object_id(&self) -> u64 {
        self.object_id
    }

    /// Returns whether this entry is active.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

// ======================================================================
// Refcount tracker
// ======================================================================

/// Tracks all refcounted objects for debugging.
pub struct RefcountTracker {
    /// Tracked refcounts.
    entries: [TrackedRefcount; MAX_REFCOUNTS],
    /// Number of active entries.
    count: usize,
    /// Global statistics.
    stats: RefcountStats,
}

impl RefcountTracker {
    /// Creates a new tracker.
    pub const fn new() -> Self {
        Self {
            entries: [const { TrackedRefcount::new() }; MAX_REFCOUNTS],
            count: 0,
            stats: RefcountStats::new(),
        }
    }

    /// Returns the number of tracked objects.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns the global stats.
    pub fn stats(&self) -> &RefcountStats {
        &self.stats
    }

    /// Registers a new refcounted object.
    pub fn register(&mut self, object_id: u64, now_ns: u64) -> Result<usize> {
        let slot = self
            .entries
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;
        self.entries[slot].rc.init();
        self.entries[slot].object_id = object_id;
        self.entries[slot].active = true;
        self.entries[slot].created_ns = now_ns;
        self.entries[slot].ops_count = 0;
        self.count += 1;
        Ok(slot)
    }

    /// Increments a tracked object's refcount.
    pub fn inc(&mut self, object_id: u64) -> Result<()> {
        let slot = self.find(object_id)?;
        let warn = self.entries[slot].rc.inc();
        self.entries[slot].ops_count += 1;
        self.stats.record_inc(warn);
        Ok(())
    }

    /// Decrements and potentially frees a tracked object.
    pub fn dec_and_test(&mut self, object_id: u64) -> Result<bool> {
        let slot = self.find(object_id)?;
        self.entries[slot].ops_count += 1;
        self.stats.record_dec(None);
        let freed = self.entries[slot].rc.dec_and_test()?;
        if freed {
            self.entries[slot].active = false;
            self.count = self.count.saturating_sub(1);
        }
        Ok(freed)
    }

    /// Returns the refcount value for an object.
    pub fn read(&self, object_id: u64) -> Result<u32> {
        let slot = self.find(object_id)?;
        Ok(self.entries[slot].rc.read())
    }

    /// Finds leaked objects (non-zero refcount, very old).
    pub fn find_leaks(&self, threshold_ns: u64, now_ns: u64) -> usize {
        self.entries
            .iter()
            .filter(|e| e.active && now_ns.saturating_sub(e.created_ns) > threshold_ns)
            .count()
    }

    /// Finds a slot by object ID.
    fn find(&self, object_id: u64) -> Result<usize> {
        self.entries
            .iter()
            .position(|e| e.active && e.object_id == object_id)
            .ok_or(Error::NotFound)
    }
}
