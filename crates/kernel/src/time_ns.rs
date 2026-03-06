// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Time namespace — per-container clock virtualisation.
//!
//! Time namespaces allow processes in different containers to observe
//! different values for `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME` while
//! sharing the same underlying hardware clock.  This is achieved by
//! applying per-namespace offsets to the raw clock readings.
//!
//! `CLOCK_REALTIME` is *not* virtualised because it is expected to
//! reflect wall-clock time globally (and is already adjustable via
//! `clock_settime(2)`).
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                    TimeNsRegistry                            │
//! │                                                              │
//! │  TimeNamespace[0..MAX_TIME_NS]                               │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  id:              u64                                  │  │
//! │  │  offsets:         TimeOffset                           │  │
//! │  │    .monotonic_offset_ns:  i64                          │  │
//! │  │    .boottime_offset_ns:   i64                          │  │
//! │  │  process_count:   u32                                  │  │
//! │  │  frozen:          bool                                 │  │
//! │  │  active:          bool                                 │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  Root namespace (id 0) always has zero offsets.              │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # POSIX Clocks Supported
//!
//! | Clock              | Virtualised? | Notes                      |
//! |--------------------|--------------|----------------------------|
//! | `CLOCK_MONOTONIC`  | Yes          | Per-NS monotonic offset    |
//! | `CLOCK_BOOTTIME`   | Yes          | Per-NS boottime offset     |
//! | `CLOCK_REALTIME`   | No           | Always global wall clock   |
//!
//! # Reference
//!
//! Linux `kernel/time/namespace.c`, `time_namespaces(7)`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum number of concurrent time namespaces.
const MAX_TIME_NS: usize = 32;

/// Root (initial) namespace ID.
const ROOT_NS_ID: u64 = 0;

// ══════════════════════════════════════════════════════════════
// ClockId — supported POSIX clocks
// ══════════════════════════════════════════════════════════════

/// Supported POSIX clock identifiers for time namespace offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockId {
    /// `CLOCK_MONOTONIC` — monotonically increasing since boot.
    Monotonic,
    /// `CLOCK_BOOTTIME` — monotonic including suspend time.
    Boottime,
}

impl ClockId {
    /// Display name for diagnostics.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Monotonic => "CLOCK_MONOTONIC",
            Self::Boottime => "CLOCK_BOOTTIME",
        }
    }
}

// ══════════════════════════════════════════════════════════════
// TimeOffset — per-namespace clock offsets
// ══════════════════════════════════════════════════════════════

/// Per-namespace clock offsets in nanoseconds.
///
/// These offsets are *added* to the raw hardware clock reading when
/// a process in this namespace reads the clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeOffset {
    /// Offset applied to `CLOCK_MONOTONIC` (nanoseconds).
    pub monotonic_offset_ns: i64,
    /// Offset applied to `CLOCK_BOOTTIME` (nanoseconds).
    pub boottime_offset_ns: i64,
}

impl TimeOffset {
    /// Zero offsets (root namespace default).
    pub const fn zero() -> Self {
        Self {
            monotonic_offset_ns: 0,
            boottime_offset_ns: 0,
        }
    }

    /// Create offsets with the given values.
    pub const fn new(monotonic_ns: i64, boottime_ns: i64) -> Self {
        Self {
            monotonic_offset_ns: monotonic_ns,
            boottime_offset_ns: boottime_ns,
        }
    }

    /// Get the offset for a specific clock.
    pub const fn offset_for(&self, clock: ClockId) -> i64 {
        match clock {
            ClockId::Monotonic => self.monotonic_offset_ns,
            ClockId::Boottime => self.boottime_offset_ns,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// TimeNamespaceState — lifecycle state
// ══════════════════════════════════════════════════════════════

/// Lifecycle state of a time namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeNamespaceState {
    /// Slot is unused.
    Free,
    /// Namespace is active and may have processes.
    Active,
    /// Namespace is frozen (offsets are locked, no new processes
    /// may enter).
    Frozen,
}

impl Default for TimeNamespaceState {
    fn default() -> Self {
        Self::Free
    }
}

// ══════════════════════════════════════════════════════════════
// TimeNamespace — single namespace instance
// ══════════════════════════════════════════════════════════════

/// A single time namespace.
#[derive(Debug, Clone, Copy)]
pub struct TimeNamespace {
    /// Unique namespace identifier.
    pub id: u64,
    /// Clock offsets applied to processes in this namespace.
    pub offsets: TimeOffset,
    /// Number of processes currently in this namespace.
    pub process_count: u32,
    /// Lifecycle state.
    pub state: TimeNamespaceState,
    /// Tick at which this namespace was created.
    pub created_tick: u64,
}

impl TimeNamespace {
    /// Create an empty (free) namespace slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            offsets: TimeOffset::zero(),
            process_count: 0,
            state: TimeNamespaceState::Free,
            created_tick: 0,
        }
    }

    /// Returns `true` if this slot is free.
    pub const fn is_free(&self) -> bool {
        matches!(self.state, TimeNamespaceState::Free)
    }

    /// Returns `true` if this namespace is active.
    pub const fn is_active(&self) -> bool {
        matches!(self.state, TimeNamespaceState::Active)
    }

    /// Returns `true` if this namespace is frozen.
    pub const fn is_frozen(&self) -> bool {
        matches!(self.state, TimeNamespaceState::Frozen)
    }
}

// ══════════════════════════════════════════════════════════════
// TimeNsStats — statistics
// ══════════════════════════════════════════════════════════════

/// Registry-level statistics.
#[derive(Debug, Clone, Copy)]
pub struct TimeNsStats {
    /// Total namespaces ever created.
    pub total_created: u64,
    /// Total namespaces destroyed.
    pub total_destroyed: u64,
    /// Current active namespace count.
    pub active_count: u32,
    /// Total enter operations.
    pub total_enters: u64,
    /// Total leave operations.
    pub total_leaves: u64,
    /// Total offset lookups.
    pub total_offset_lookups: u64,
}

impl TimeNsStats {
    /// Zero-initialised stats.
    const fn new() -> Self {
        Self {
            total_created: 0,
            total_destroyed: 0,
            active_count: 0,
            total_enters: 0,
            total_leaves: 0,
            total_offset_lookups: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// TimeNsRegistry — namespace manager
// ══════════════════════════════════════════════════════════════

/// Registry managing all time namespaces.
///
/// Slot 0 is always the root namespace with zero offsets.
pub struct TimeNsRegistry {
    /// Namespace slots.
    namespaces: [TimeNamespace; MAX_TIME_NS],
    /// Next unique namespace ID to assign.
    next_id: u64,
    /// Statistics.
    stats: TimeNsStats,
    /// Whether the registry has been initialised.
    initialised: bool,
}

impl Default for TimeNsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeNsRegistry {
    /// Create a new registry.
    ///
    /// Slot 0 is pre-populated as the root namespace.
    pub const fn new() -> Self {
        let mut ns = [const { TimeNamespace::empty() }; MAX_TIME_NS];
        // Initialise the root namespace (slot 0).
        ns[0] = TimeNamespace {
            id: ROOT_NS_ID,
            offsets: TimeOffset::zero(),
            process_count: 0,
            state: TimeNamespaceState::Active,
            created_tick: 0,
        };
        Self {
            namespaces: ns,
            next_id: 1,
            stats: TimeNsStats::new(),
            initialised: false,
        }
    }

    /// Initialise the registry.  Must be called once at boot.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.stats.active_count = 1; // root NS
        self.initialised = true;
        Ok(())
    }

    // ── Create / destroy ─────────────────────────────────────

    /// Create a new time namespace with the given clock offsets.
    ///
    /// Returns the namespace ID of the newly created namespace.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if all slots are occupied.
    pub fn create(&mut self, offsets: TimeOffset, tick: u64) -> Result<u64> {
        // Find a free slot (skip slot 0 = root).
        let slot = self.find_free_slot()?;

        let id = self.next_id;
        self.next_id += 1;

        self.namespaces[slot] = TimeNamespace {
            id,
            offsets,
            process_count: 0,
            state: TimeNamespaceState::Active,
            created_tick: tick,
        };

        self.stats.total_created += 1;
        self.stats.active_count += 1;

        Ok(id)
    }

    /// Destroy a time namespace.
    ///
    /// The namespace must have zero processes.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the namespace ID is not found.
    /// - `InvalidArgument` if trying to destroy the root namespace.
    /// - `Busy` if the namespace still has processes.
    pub fn destroy(&mut self, ns_id: u64) -> Result<()> {
        if ns_id == ROOT_NS_ID {
            return Err(Error::InvalidArgument);
        }
        let slot = self.find_slot_by_id(ns_id)?;

        if self.namespaces[slot].process_count > 0 {
            return Err(Error::Busy);
        }

        self.namespaces[slot] = TimeNamespace::empty();
        self.stats.total_destroyed += 1;
        self.stats.active_count = self.stats.active_count.saturating_sub(1);

        Ok(())
    }

    // ── Enter / leave ────────────────────────────────────────

    /// A process enters this time namespace.
    ///
    /// Increments the process count.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the namespace ID is not found.
    /// - `PermissionDenied` if the namespace is frozen.
    pub fn enter(&mut self, ns_id: u64) -> Result<()> {
        let slot = self.find_slot_by_id(ns_id)?;

        if self.namespaces[slot].is_frozen() {
            return Err(Error::PermissionDenied);
        }

        self.namespaces[slot].process_count += 1;
        self.stats.total_enters += 1;
        Ok(())
    }

    /// A process leaves this time namespace.
    ///
    /// Decrements the process count.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the namespace ID is not found.
    /// - `InvalidArgument` if the process count is already zero.
    pub fn leave(&mut self, ns_id: u64) -> Result<()> {
        let slot = self.find_slot_by_id(ns_id)?;

        if self.namespaces[slot].process_count == 0 {
            return Err(Error::InvalidArgument);
        }

        self.namespaces[slot].process_count -= 1;
        self.stats.total_leaves += 1;
        Ok(())
    }

    // ── Freeze / unfreeze ────────────────────────────────────

    /// Freeze a namespace: lock offsets and prevent new processes
    /// from entering.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the namespace ID is not found.
    /// - `InvalidArgument` if trying to freeze the root namespace.
    pub fn freeze(&mut self, ns_id: u64) -> Result<()> {
        if ns_id == ROOT_NS_ID {
            return Err(Error::InvalidArgument);
        }
        let slot = self.find_slot_by_id(ns_id)?;
        self.namespaces[slot].state = TimeNamespaceState::Frozen;
        Ok(())
    }

    /// Unfreeze a namespace: allow offset changes and new processes.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the namespace ID is not found.
    pub fn unfreeze(&mut self, ns_id: u64) -> Result<()> {
        let slot = self.find_slot_by_id(ns_id)?;
        if self.namespaces[slot].is_frozen() {
            self.namespaces[slot].state = TimeNamespaceState::Active;
        }
        Ok(())
    }

    // ── Offset queries ───────────────────────────────────────

    /// Get the clock offset for a specific clock in a namespace.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the namespace ID is not found.
    pub fn get_clock_offset(&mut self, ns_id: u64, clock: ClockId) -> Result<i64> {
        let slot = self.find_slot_by_id(ns_id)?;
        self.stats.total_offset_lookups += 1;
        Ok(self.namespaces[slot].offsets.offset_for(clock))
    }

    /// Apply the namespace offset to a raw tick/nanosecond value.
    ///
    /// Returns the adjusted value: `ticks + offset`.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the namespace ID is not found.
    pub fn apply_offset(&mut self, ns_id: u64, clock: ClockId, ticks: u64) -> Result<u64> {
        let offset = self.get_clock_offset(ns_id, clock)?;
        // Saturating add to prevent underflow/overflow.
        let adjusted = if offset >= 0 {
            ticks.saturating_add(offset as u64)
        } else {
            ticks.saturating_sub(offset.unsigned_abs())
        };
        Ok(adjusted)
    }

    /// Update the offsets for a namespace.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the namespace ID is not found.
    /// - `InvalidArgument` if trying to modify the root namespace.
    /// - `PermissionDenied` if the namespace is frozen.
    pub fn set_offsets(&mut self, ns_id: u64, offsets: TimeOffset) -> Result<()> {
        if ns_id == ROOT_NS_ID {
            return Err(Error::InvalidArgument);
        }
        let slot = self.find_slot_by_id(ns_id)?;
        if self.namespaces[slot].is_frozen() {
            return Err(Error::PermissionDenied);
        }
        self.namespaces[slot].offsets = offsets;
        Ok(())
    }

    // ── Query / diagnostics ──────────────────────────────────

    /// Look up a namespace by ID (read-only).
    ///
    /// # Errors
    ///
    /// - `NotFound` if the namespace ID is not found.
    pub fn get(&self, ns_id: u64) -> Result<&TimeNamespace> {
        let slot = self.find_slot_by_id_const(ns_id)?;
        Ok(&self.namespaces[slot])
    }

    /// Return the root namespace (always slot 0).
    pub fn root(&self) -> &TimeNamespace {
        &self.namespaces[0]
    }

    /// Return a snapshot of statistics.
    pub fn stats(&self) -> TimeNsStats {
        self.stats
    }

    /// Return the number of active (non-free) namespaces.
    pub fn active_count(&self) -> u32 {
        self.stats.active_count
    }

    /// List all active namespace IDs.
    ///
    /// Returns an array and the number of valid entries.
    pub fn list_active(&self) -> ([u64; MAX_TIME_NS], usize) {
        let mut ids = [0u64; MAX_TIME_NS];
        let mut count = 0;
        for ns in &self.namespaces {
            if !ns.is_free() {
                ids[count] = ns.id;
                count += 1;
            }
        }
        (ids, count)
    }

    // ── Internals ────────────────────────────────────────────

    /// Find a free slot (excluding slot 0).
    fn find_free_slot(&self) -> Result<usize> {
        self.namespaces[1..]
            .iter()
            .position(|ns| ns.is_free())
            .map(|i| i + 1) // adjust for skipping slot 0
            .ok_or(Error::OutOfMemory)
    }

    /// Find the slot index for a given namespace ID.
    fn find_slot_by_id(&self, ns_id: u64) -> Result<usize> {
        self.namespaces
            .iter()
            .position(|ns| !ns.is_free() && ns.id == ns_id)
            .ok_or(Error::NotFound)
    }

    /// Const-compatible version of `find_slot_by_id`.
    fn find_slot_by_id_const(&self, ns_id: u64) -> Result<usize> {
        let mut i = 0;
        while i < MAX_TIME_NS {
            if !self.namespaces[i].is_free() && self.namespaces[i].id == ns_id {
                return Ok(i);
            }
            i += 1;
        }
        Err(Error::NotFound)
    }
}
