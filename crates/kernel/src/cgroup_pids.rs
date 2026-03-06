// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cgroup v2 PID controller for process count limiting.
//!
//! Implements the `pids` controller from Linux cgroups v2 with:
//! - Per-group PID count limiting (`max` semantics)
//! - Fork-guard checking (`can_fork`)
//! - PID attachment/detachment with deduplication
//! - Event accounting for limit-hit occurrences
//!
//! # Types
//!
//! - [`PidsStats`] — current count, limit, and events counters
//! - [`PidsCgroupController`] — a single PID cgroup instance
//! - [`PidsCgroupRegistry`] — system-wide registry of PID cgroups

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum number of PID cgroup controllers in the system.
const MAX_PIDS_CGROUPS: usize = 64;

/// Maximum number of PIDs per PID cgroup controller.
const MAX_PIDS_PER_GROUP: usize = 64;

/// Maximum name length in bytes.
const MAX_NAME_LEN: usize = 64;

/// Limit value meaning unlimited (no PID cap).
const LIMIT_UNLIMITED: i64 = -1;

// ── PidsStats ──────────────────────────────────────────────────────

/// PID usage and event statistics for a cgroup.
///
/// Tracks the current number of attached PIDs, the configured
/// limit, and how many times a fork or PID addition was rejected
/// because the limit was reached.
#[derive(Debug, Clone, Copy, Default)]
pub struct PidsStats {
    /// Current number of PIDs in this cgroup.
    pub current: u64,
    /// Maximum allowed PIDs (`-1` = unlimited).
    pub limit: i64,
    /// Number of times the PID limit was hit (fork rejected).
    pub events_max: u64,
}

// ── PidsCgroupController ───────────────────────────────────────────

/// A single PID cgroup controller instance.
///
/// Manages PID count limiting and fork-guard checking for a set
/// of attached process IDs.
#[derive(Debug, Clone, Copy)]
pub struct PidsCgroupController {
    /// Unique identifier for this controller.
    pub id: u64,
    /// Controller name (UTF-8 bytes, null-padded).
    pub name: [u8; MAX_NAME_LEN],
    /// Name length in bytes.
    pub name_len: usize,
    /// Maximum allowed PIDs (`-1` = unlimited).
    pub max_pids: i64,
    /// Attached process IDs.
    pub pids: [u64; MAX_PIDS_PER_GROUP],
    /// Number of attached PIDs.
    pub pid_count: usize,
    /// Usage and event statistics.
    pub stats: PidsStats,
    /// Whether this controller is enabled.
    pub enabled: bool,
    /// Whether this slot is actively in use.
    pub in_use: bool,
}

impl PidsCgroupController {
    /// Creates an empty (inactive) controller slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            max_pids: LIMIT_UNLIMITED,
            pids: [0u64; MAX_PIDS_PER_GROUP],
            pid_count: 0,
            stats: PidsStats {
                current: 0,
                limit: LIMIT_UNLIMITED,
                events_max: 0,
            },
            enabled: false,
            in_use: false,
        }
    }

    /// Sets the maximum PID limit for this controller.
    ///
    /// `limit` must be `-1` (unlimited) or a positive value.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` if `limit` is zero or a
    /// negative value other than `-1`.
    pub fn set_max(&mut self, limit: i64) -> Result<()> {
        if limit != LIMIT_UNLIMITED && limit <= 0 {
            return Err(Error::InvalidArgument);
        }
        self.max_pids = limit;
        self.stats.limit = limit;
        Ok(())
    }

    /// Adds a PID to this controller.
    ///
    /// # Errors
    ///
    /// - `Error::AlreadyExists` — PID is already attached.
    /// - `Error::OutOfMemory` — PID array is full.
    /// - `Error::Busy` — adding this PID would exceed the
    ///   configured limit.
    pub fn add_pid(&mut self, pid: u64) -> Result<()> {
        if self.pids[..self.pid_count].contains(&pid) {
            return Err(Error::AlreadyExists);
        }
        if !self.can_fork() {
            self.stats.events_max = self.stats.events_max.saturating_add(1);
            return Err(Error::Busy);
        }
        if self.pid_count >= MAX_PIDS_PER_GROUP {
            return Err(Error::OutOfMemory);
        }
        self.pids[self.pid_count] = pid;
        self.pid_count += 1;
        self.stats.current = self.pid_count as u64;
        Ok(())
    }

    /// Removes a PID from this controller.
    ///
    /// # Errors
    ///
    /// Returns `Error::NotFound` if the PID is not attached.
    pub fn remove_pid(&mut self, pid: u64) -> Result<()> {
        let pos = self.pids[..self.pid_count]
            .iter()
            .position(|&p| p == pid)
            .ok_or(Error::NotFound)?;

        // Swap-remove: move last element into the vacated slot.
        self.pid_count -= 1;
        if pos < self.pid_count {
            self.pids[pos] = self.pids[self.pid_count];
        }
        self.pids[self.pid_count] = 0;
        self.stats.current = self.pid_count as u64;
        Ok(())
    }

    /// Returns whether a PID is attached to this controller.
    pub fn has_pid(&self, pid: u64) -> bool {
        self.pids[..self.pid_count].contains(&pid)
    }

    /// Checks whether a new process can be forked under this
    /// controller.
    ///
    /// Returns `true` if the PID limit is unlimited (`-1`) or the
    /// current count is below the configured maximum.
    pub fn can_fork(&self) -> bool {
        if self.max_pids == LIMIT_UNLIMITED {
            return true;
        }
        // max_pids is positive here (validated in set_max).
        (self.pid_count as i64) < self.max_pids
    }

    /// Returns a reference to the current PID statistics.
    pub fn get_stats(&self) -> &PidsStats {
        &self.stats
    }
}

// ── PidsCgroupRegistry ─────────────────────────────────────────────

/// System-wide registry of PID cgroup controllers.
///
/// Manages up to [`MAX_PIDS_CGROUPS`] controllers in a fixed-size
/// array. Each controller is identified by a unique `u64` ID
/// assigned at creation time.
pub struct PidsCgroupRegistry {
    /// Fixed-size array of controller slots.
    controllers: [PidsCgroupController; MAX_PIDS_CGROUPS],
    /// Next controller ID to assign.
    next_id: u64,
    /// Number of active controllers.
    count: usize,
}

impl Default for PidsCgroupRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PidsCgroupRegistry {
    /// Creates a new, empty registry.
    pub const fn new() -> Self {
        const EMPTY: PidsCgroupController = PidsCgroupController::empty();
        Self {
            controllers: [EMPTY; MAX_PIDS_CGROUPS],
            next_id: 1,
            count: 0,
        }
    }

    /// Returns the number of active controllers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no controllers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Creates a new PID cgroup controller with the given name.
    ///
    /// Returns the new controller's unique ID.
    ///
    /// # Errors
    ///
    /// - `Error::InvalidArgument` — name is empty or too long.
    /// - `Error::OutOfMemory` — no free slots available.
    pub fn create(&mut self, name: &[u8]) -> Result<u64> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_PIDS_CGROUPS {
            return Err(Error::OutOfMemory);
        }

        let slot = self
            .controllers
            .iter()
            .position(|c| !c.in_use)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let ctrl = &mut self.controllers[slot];
        *ctrl = PidsCgroupController::empty();
        ctrl.id = id;
        ctrl.in_use = true;
        ctrl.enabled = true;
        ctrl.name_len = name.len();
        ctrl.name[..name.len()].copy_from_slice(name);

        self.count += 1;
        Ok(id)
    }

    /// Destroys a PID cgroup controller by ID.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — controller does not exist.
    /// - `Error::Busy` — controller still has attached PIDs.
    pub fn destroy(&mut self, id: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        if self.controllers[idx].pid_count > 0 {
            return Err(Error::Busy);
        }
        self.controllers[idx].in_use = false;
        self.controllers[idx].enabled = false;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Returns an immutable reference to a controller by ID.
    pub fn get(&self, id: u64) -> Option<&PidsCgroupController> {
        self.controllers.iter().find(|c| c.in_use && c.id == id)
    }

    /// Returns a mutable reference to a controller by ID.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut PidsCgroupController> {
        self.controllers.iter_mut().find(|c| c.in_use && c.id == id)
    }

    /// Sets the maximum PID limit for a controller.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — controller does not exist.
    /// - `Error::InvalidArgument` — invalid limit value.
    pub fn set_max(&mut self, id: u64, limit: i64) -> Result<()> {
        let idx = self.index_of(id)?;
        self.controllers[idx].set_max(limit)
    }

    /// Attaches a PID to a controller.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — controller does not exist.
    /// - `Error::AlreadyExists` — PID is already attached.
    /// - `Error::Busy` — PID limit would be exceeded.
    /// - `Error::OutOfMemory` — PID array is full.
    pub fn add_pid(&mut self, id: u64, pid: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        self.controllers[idx].add_pid(pid)
    }

    /// Detaches a PID from a controller.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — controller does not exist or PID is
    ///   not attached.
    pub fn remove_pid(&mut self, id: u64, pid: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        self.controllers[idx].remove_pid(pid)
    }

    /// Checks whether a new process can be forked under a
    /// controller.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — controller does not exist.
    pub fn can_fork(&self, id: u64) -> Result<bool> {
        let idx = self.index_of(id)?;
        Ok(self.controllers[idx].can_fork())
    }

    // ── Internal helpers ───────────────────────────────────────────

    /// Returns the index of an active controller by ID.
    fn index_of(&self, id: u64) -> Result<usize> {
        self.controllers
            .iter()
            .position(|c| c.in_use && c.id == id)
            .ok_or(Error::NotFound)
    }
}
