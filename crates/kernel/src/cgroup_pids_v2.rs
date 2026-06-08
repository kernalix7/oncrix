// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cgroup v2 PIDs controller.
//!
//! Limits the number of processes (tasks) that can be created within
//! a cgroup hierarchy. Prevents fork bombs and runaway process
//! creation from exhausting the system PID space.
//!
//! # Architecture
//!
//! ```text
//! PidsCgroupV2
//!  ├── groups[MAX_GROUPS]
//!  │    ├── id, parent_id
//!  │    ├── current: u64   (tasks currently in cgroup)
//!  │    ├── limit: u64     (pids.max)
//!  │    └── events: PidsEvents
//!  └── global stats
//! ```
//!
//! # Reference
//!
//! Linux `kernel/cgroup/pids.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum number of PID cgroups.
const MAX_GROUPS: usize = 256;

/// Maximum parent-chain depth for hierarchy walks.
///
/// Bounded by the maximum number of distinct groups that can exist.
/// Any cycle that slipped past creation-time validation is terminated here.
const CGROUP_MAX_DEPTH: usize = MAX_GROUPS;

/// Value indicating unlimited PIDs.
const PIDS_UNLIMITED: u64 = u64::MAX;

// ══════════════════════════════════════════════════════════════
// PidsEvents
// ══════════════════════════════════════════════════════════════

/// Event counters for a PID cgroup.
#[derive(Debug, Clone, Copy)]
pub struct PidsEvents {
    /// Number of times fork was denied due to limit.
    pub max_hit: u64,
}

impl PidsEvents {
    /// Create zeroed events.
    const fn new() -> Self {
        Self { max_hit: 0 }
    }
}

// ══════════════════════════════════════════════════════════════
// PidsCgroupEntry
// ══════════════════════════════════════════════════════════════

/// A single PIDs cgroup entry.
#[derive(Debug, Clone, Copy)]
pub struct PidsCgroupEntry {
    /// Cgroup identifier.
    pub id: u32,
    /// Parent cgroup ID (0 = root).
    pub parent_id: u32,
    /// Current number of tasks in this cgroup.
    pub current: u64,
    /// Maximum allowed tasks (pids.max).
    pub limit: u64,
    /// Peak task count observed.
    pub peak: u64,
    /// Event counters.
    pub events: PidsEvents,
    /// Whether this entry is active.
    pub active: bool,
}

impl PidsCgroupEntry {
    /// Create an inactive entry.
    const fn empty() -> Self {
        Self {
            id: 0,
            parent_id: 0,
            current: 0,
            limit: PIDS_UNLIMITED,
            peak: 0,
            events: PidsEvents::new(),
            active: false,
        }
    }

    /// Returns `true` if a new task can be charged.
    pub fn can_charge(&self) -> bool {
        self.limit == PIDS_UNLIMITED || self.current < self.limit
    }
}

// ══════════════════════════════════════════════════════════════
// PidsCgroupV2
// ══════════════════════════════════════════════════════════════

/// Cgroup v2 PIDs controller subsystem.
pub struct PidsCgroupV2 {
    /// Cgroup entries.
    groups: [PidsCgroupEntry; MAX_GROUPS],
    /// Next cgroup ID.
    next_id: u32,
    /// Total forks denied.
    pub total_denied: u64,
    /// Total groups created.
    pub total_created: u64,
}

impl PidsCgroupV2 {
    /// Create a new PIDs controller.
    pub const fn new() -> Self {
        Self {
            groups: [const { PidsCgroupEntry::empty() }; MAX_GROUPS],
            next_id: 1,
            total_denied: 0,
            total_created: 0,
        }
    }

    /// Create a new PIDs cgroup.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `parent_id` is non-zero and does not refer to
    ///   an existing active group.  This rejects self-referential and
    ///   forward-referencing parent IDs, which would otherwise cause infinite
    ///   loops in the hierarchy walks.
    /// - `OutOfMemory` if no free slots remain or the ID counter would overflow.
    pub fn create_group(&mut self, parent_id: u32) -> Result<u32> {
        // Validate parent before touching any state.
        // A non-zero parent must already exist; zero means top-level (root).
        // Because IDs are monotonically increasing, a parent_id equal to
        // next_id (or beyond) can never match an active group, so self-cycles
        // and forward-references are rejected here.
        if parent_id != 0 && self.find_group(parent_id).is_err() {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .groups
            .iter()
            .position(|g| !g.active)
            .ok_or(Error::OutOfMemory)?;

        // Compute new next_id with overflow check BEFORE writing to the slot,
        // so a failure leaves the groups array unmodified.
        let id = self.next_id;
        self.next_id = id.checked_add(1).ok_or(Error::OutOfMemory)?;

        self.groups[slot] = PidsCgroupEntry {
            id,
            parent_id,
            active: true,
            ..PidsCgroupEntry::empty()
        };
        self.total_created += 1;
        Ok(id)
    }

    /// Remove a PIDs cgroup.
    pub fn remove_group(&mut self, id: u32) -> Result<()> {
        let slot = self.find_group(id)?;
        if self.groups[slot].current > 0 {
            return Err(Error::Busy);
        }
        self.groups[slot] = PidsCgroupEntry::empty();
        Ok(())
    }

    /// Set the PIDs limit for a cgroup.
    pub fn set_limit(&mut self, id: u32, limit: u64) -> Result<()> {
        let slot = self.find_group(id)?;
        self.groups[slot].limit = limit;
        Ok(())
    }

    /// Charge a new task (fork/clone) to a cgroup.
    ///
    /// Also checks all ancestors up to root.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the cgroup or any ancestor has reached
    ///   its PID limit.
    pub fn charge(&mut self, id: u32) -> Result<()> {
        // First check the entire hierarchy can accept.
        if !self.can_charge_hierarchy(id) {
            let slot = self.find_group(id)?;
            self.groups[slot].events.max_hit += 1;
            self.total_denied += 1;
            return Err(Error::OutOfMemory);
        }

        // Charge along the hierarchy.
        let mut current_id = id;
        let mut hops = 0usize;
        loop {
            hops += 1;
            if hops > CGROUP_MAX_DEPTH {
                break;
            }
            if let Ok(slot) = self.find_group(current_id) {
                self.groups[slot].current += 1;
                if self.groups[slot].current > self.groups[slot].peak {
                    self.groups[slot].peak = self.groups[slot].current;
                }
                let pid = self.groups[slot].parent_id;
                if pid == 0 {
                    break;
                }
                current_id = pid;
            } else {
                break;
            }
        }
        Ok(())
    }

    /// Uncharge a task (exit) from a cgroup.
    pub fn uncharge(&mut self, id: u32) -> Result<()> {
        let mut current_id = id;
        let mut hops = 0usize;
        loop {
            hops += 1;
            if hops > CGROUP_MAX_DEPTH {
                break;
            }
            if let Ok(slot) = self.find_group(current_id) {
                self.groups[slot].current = self.groups[slot].current.saturating_sub(1);
                let pid = self.groups[slot].parent_id;
                if pid == 0 {
                    break;
                }
                current_id = pid;
            } else {
                break;
            }
        }
        Ok(())
    }

    /// Return cgroup entry by ID.
    pub fn get_group(&self, id: u32) -> Result<&PidsCgroupEntry> {
        let slot = self.find_group(id)?;
        Ok(&self.groups[slot])
    }

    /// Return the number of active cgroups.
    pub fn active_count(&self) -> usize {
        self.groups.iter().filter(|g| g.active).count()
    }

    // ── Internal ─────────────────────────────────────────────

    fn find_group(&self, id: u32) -> Result<usize> {
        self.groups
            .iter()
            .position(|g| g.active && g.id == id)
            .ok_or(Error::NotFound)
    }

    fn can_charge_hierarchy(&self, id: u32) -> bool {
        let mut current_id = id;
        let mut hops = 0usize;
        loop {
            hops += 1;
            if hops > CGROUP_MAX_DEPTH {
                break;
            }
            if let Some(slot) = self
                .groups
                .iter()
                .position(|g| g.active && g.id == current_id)
            {
                if !self.groups[slot].can_charge() {
                    return false;
                }
                let pid = self.groups[slot].parent_id;
                if pid == 0 {
                    break;
                }
                current_id = pid;
            } else {
                break;
            }
        }
        true
    }
}
