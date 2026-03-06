// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cgroup freezer v2 — cgroup v2 freezer controller.
//!
//! The v2 freezer integrates with the unified cgroup hierarchy to
//! freeze and thaw entire cgroup subtrees.  Unlike v1, freezing is
//! recursive and propagates to child cgroups.
//!
//! # Reference
//!
//! Linux `kernel/cgroup/freezer.c`, `include/linux/cgroup.h`.

use oncrix_lib::{Error, Result};

const MAX_CGROUPS: usize = 256;

/// Freeze state of a cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FreezeState {
    /// Slot is free.
    Free = 0,
    /// Cgroup is running (thawed).
    Thawed = 1,
    /// Freeze request pending (transitioning).
    Freezing = 2,
    /// Fully frozen.
    Frozen = 3,
    /// Thaw request pending (transitioning).
    Thawing = 4,
}

impl FreezeState {
    /// Display name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Thawed => "thawed",
            Self::Freezing => "freezing",
            Self::Frozen => "frozen",
            Self::Thawing => "thawing",
        }
    }
}

/// A cgroup freezer entry.
#[derive(Debug, Clone, Copy)]
pub struct FreezerEntry {
    /// Cgroup identifier.
    pub cgroup_id: u64,
    /// Parent cgroup ID (0 = root).
    pub parent_id: u64,
    /// Current freeze state.
    pub state: FreezeState,
    /// Number of tasks in this cgroup.
    pub nr_tasks: u32,
    /// Number of frozen tasks.
    pub nr_frozen: u32,
    /// Whether self-freezing was requested.
    pub self_freezing: bool,
    /// Whether parent-initiated freeze.
    pub parent_freezing: bool,
    /// Freeze timestamp.
    pub freeze_timestamp: u64,
}

impl FreezerEntry {
    const fn empty() -> Self {
        Self {
            cgroup_id: 0,
            parent_id: 0,
            state: FreezeState::Free,
            nr_tasks: 0,
            nr_frozen: 0,
            self_freezing: false,
            parent_freezing: false,
            freeze_timestamp: 0,
        }
    }

    /// Returns `true` if the slot is in use.
    pub const fn is_active(&self) -> bool {
        !matches!(self.state, FreezeState::Free)
    }
}

/// Statistics for the v2 freezer.
#[derive(Debug, Clone, Copy)]
pub struct FreezerV2Stats {
    /// Total freeze requests.
    pub total_freeze: u64,
    /// Total thaw requests.
    pub total_thaw: u64,
    /// Total tasks frozen.
    pub total_tasks_frozen: u64,
    /// Total tasks thawed.
    pub total_tasks_thawed: u64,
}

impl FreezerV2Stats {
    const fn new() -> Self {
        Self {
            total_freeze: 0,
            total_thaw: 0,
            total_tasks_frozen: 0,
            total_tasks_thawed: 0,
        }
    }
}

/// Top-level cgroup v2 freezer subsystem.
pub struct CgroupFreezerV2 {
    /// Cgroup entries.
    entries: [FreezerEntry; MAX_CGROUPS],
    /// Statistics.
    stats: FreezerV2Stats,
    /// Whether the subsystem is initialised.
    initialised: bool,
}

impl Default for CgroupFreezerV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl CgroupFreezerV2 {
    /// Create a new v2 freezer subsystem.
    pub const fn new() -> Self {
        Self {
            entries: [const { FreezerEntry::empty() }; MAX_CGROUPS],
            stats: FreezerV2Stats::new(),
            initialised: false,
        }
    }

    /// Initialise the subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.initialised = true;
        Ok(())
    }

    /// Register a cgroup for freeze management.
    pub fn register(&mut self, cgroup_id: u64, parent_id: u64) -> Result<usize> {
        let slot = self
            .entries
            .iter()
            .position(|e| matches!(e.state, FreezeState::Free))
            .ok_or(Error::OutOfMemory)?;

        self.entries[slot] = FreezerEntry {
            cgroup_id,
            parent_id,
            state: FreezeState::Thawed,
            nr_tasks: 0,
            nr_frozen: 0,
            self_freezing: false,
            parent_freezing: false,
            freeze_timestamp: 0,
        };
        Ok(slot)
    }

    /// Freeze a cgroup.
    pub fn freeze(&mut self, cgroup_id: u64, timestamp: u64) -> Result<()> {
        let slot = self.find_cgroup(cgroup_id)?;
        if matches!(
            self.entries[slot].state,
            FreezeState::Frozen | FreezeState::Freezing
        ) {
            return Ok(());
        }

        self.entries[slot].state = FreezeState::Freezing;
        self.entries[slot].self_freezing = true;
        self.entries[slot].freeze_timestamp = timestamp;
        self.stats.total_freeze += 1;

        // Propagate to children.
        let id = cgroup_id;
        for i in 0..MAX_CGROUPS {
            if self.entries[i].is_active()
                && self.entries[i].parent_id == id
                && !matches!(
                    self.entries[i].state,
                    FreezeState::Frozen | FreezeState::Freezing
                )
            {
                self.entries[i].state = FreezeState::Freezing;
                self.entries[i].parent_freezing = true;
            }
        }

        Ok(())
    }

    /// Complete the freeze (all tasks stopped).
    pub fn complete_freeze(&mut self, cgroup_id: u64) -> Result<()> {
        let slot = self.find_cgroup(cgroup_id)?;
        if !matches!(self.entries[slot].state, FreezeState::Freezing) {
            return Err(Error::InvalidArgument);
        }
        let frozen = self.entries[slot].nr_tasks;
        self.entries[slot].state = FreezeState::Frozen;
        self.entries[slot].nr_frozen = frozen;
        self.stats.total_tasks_frozen += frozen as u64;
        Ok(())
    }

    /// Thaw a cgroup.
    pub fn thaw(&mut self, cgroup_id: u64) -> Result<()> {
        let slot = self.find_cgroup(cgroup_id)?;
        if matches!(self.entries[slot].state, FreezeState::Thawed) {
            return Ok(());
        }

        let thawed = self.entries[slot].nr_frozen;
        self.entries[slot].state = FreezeState::Thawed;
        self.entries[slot].self_freezing = false;
        self.entries[slot].parent_freezing = false;
        self.entries[slot].nr_frozen = 0;
        self.stats.total_thaw += 1;
        self.stats.total_tasks_thawed += thawed as u64;

        // Propagate thaw to children.
        let id = cgroup_id;
        for i in 0..MAX_CGROUPS {
            if self.entries[i].is_active()
                && self.entries[i].parent_id == id
                && self.entries[i].parent_freezing
            {
                self.entries[i].state = FreezeState::Thawed;
                self.entries[i].parent_freezing = false;
                self.entries[i].nr_frozen = 0;
            }
        }

        Ok(())
    }

    /// Update task count for a cgroup.
    pub fn update_task_count(&mut self, cgroup_id: u64, nr_tasks: u32) -> Result<()> {
        let slot = self.find_cgroup(cgroup_id)?;
        self.entries[slot].nr_tasks = nr_tasks;
        Ok(())
    }

    /// Return an entry.
    pub fn entry(&self, cgroup_id: u64) -> Result<&FreezerEntry> {
        let slot = self.find_cgroup(cgroup_id)?;
        Ok(&self.entries[slot])
    }

    /// Return statistics.
    pub fn stats(&self) -> FreezerV2Stats {
        self.stats
    }

    /// Return the number of frozen cgroups.
    pub fn frozen_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| matches!(e.state, FreezeState::Frozen))
            .count()
    }

    fn find_cgroup(&self, cgroup_id: u64) -> Result<usize> {
        self.entries
            .iter()
            .position(|e| e.is_active() && e.cgroup_id == cgroup_id)
            .ok_or(Error::NotFound)
    }
}
