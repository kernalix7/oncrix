// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Timer slack for power savings.
//!
//! Each task has a configurable "timer slack" value that allows the
//! kernel to coalesce nearby timer expirations. When a timer is armed,
//! its actual deadline is extended by at most `timer_slack_ns`, letting
//! the kernel batch wakeups and reduce the number of idle-exit events.
//!
//! This is controlled via `prctl(PR_SET_TIMERSLACK)` and has no effect
//! on real-time tasks.
//!
//! # Design
//!
//! ```text
//! TimerSlackManager
//!  ├── entries: [SlackEntry; MAX_TASKS]
//!  ├── default_slack_ns: u64
//!  └── stats: SlackStats
//! ```
//!
//! The timer subsystem queries a task's slack before programming the
//! hardware timer, potentially grouping multiple tasks into a single
//! interrupt.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum tasks with slack tracking.
const MAX_TASKS: usize = 4096;

/// Default timer slack (50 microseconds in nanoseconds).
const DEFAULT_SLACK_NS: u64 = 50_000;

/// Maximum allowed slack (1 second).
const MAX_SLACK_NS: u64 = 1_000_000_000;

/// Timer slack for real-time tasks (no slack).
const RT_SLACK_NS: u64 = 0;

// ======================================================================
// Types
// ======================================================================

/// Per-task timer slack entry.
#[derive(Debug, Clone, Copy)]
pub struct SlackEntry {
    /// PID of the task.
    pub pid: u64,
    /// Timer slack in nanoseconds.
    pub slack_ns: u64,
    /// Whether this is a real-time task (slack forced to 0).
    pub is_rt: bool,
    /// Whether this entry is active.
    pub active: bool,
}

impl SlackEntry {
    /// Creates an empty slack entry.
    pub const fn new() -> Self {
        Self {
            pid: 0,
            slack_ns: DEFAULT_SLACK_NS,
            is_rt: false,
            active: false,
        }
    }
}

impl Default for SlackEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a coalescing check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoalesceResult {
    /// Timer can be coalesced with an existing group.
    Coalesced,
    /// Timer must fire on its own (no nearby timers).
    Standalone,
}

impl Default for CoalesceResult {
    fn default() -> Self {
        Self::Standalone
    }
}

/// Statistics for timer slack operations.
#[derive(Debug, Clone, Copy)]
pub struct SlackStats {
    /// Number of timers that were coalesced.
    pub coalesced_count: u64,
    /// Number of timers that fired standalone.
    pub standalone_count: u64,
    /// Total nanoseconds saved by coalescing.
    pub saved_ns: u64,
    /// Number of PR_SET_TIMERSLACK calls.
    pub set_calls: u64,
}

impl SlackStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            coalesced_count: 0,
            standalone_count: 0,
            saved_ns: 0,
            set_calls: 0,
        }
    }
}

impl Default for SlackStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Timer group for coalescing nearby deadlines.
#[derive(Debug, Clone, Copy)]
pub struct TimerGroup {
    /// Earliest deadline in the group.
    pub earliest_ns: u64,
    /// Latest deadline in the group.
    pub latest_ns: u64,
    /// Number of timers in the group.
    pub count: u32,
    /// Whether this group is active.
    pub active: bool,
}

impl TimerGroup {
    /// Creates an empty timer group.
    pub const fn new() -> Self {
        Self {
            earliest_ns: 0,
            latest_ns: 0,
            count: 0,
            active: false,
        }
    }
}

impl Default for TimerGroup {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum concurrent timer groups.
const MAX_GROUPS: usize = 64;

/// Manages per-task timer slack values.
pub struct TimerSlackManager {
    /// Per-task slack entries.
    entries: [SlackEntry; MAX_TASKS],
    /// Number of active entries.
    nr_entries: usize,
    /// System-wide default slack.
    default_slack_ns: u64,
    /// Timer groups for coalescing.
    groups: [TimerGroup; MAX_GROUPS],
    /// Number of active groups.
    nr_groups: usize,
    /// Statistics.
    stats: SlackStats,
}

impl TimerSlackManager {
    /// Creates a new timer slack manager.
    pub const fn new() -> Self {
        Self {
            entries: [SlackEntry::new(); MAX_TASKS],
            nr_entries: 0,
            default_slack_ns: DEFAULT_SLACK_NS,
            groups: [TimerGroup::new(); MAX_GROUPS],
            nr_groups: 0,
            stats: SlackStats::new(),
        }
    }

    /// Registers a task with default slack.
    pub fn register_task(&mut self, pid: u64, is_rt: bool) -> Result<()> {
        if self.find_entry(pid).is_some() {
            return Err(Error::AlreadyExists);
        }
        if self.nr_entries >= MAX_TASKS {
            return Err(Error::OutOfMemory);
        }
        let slack = if is_rt {
            RT_SLACK_NS
        } else {
            self.default_slack_ns
        };
        for entry in &mut self.entries {
            if !entry.active {
                *entry = SlackEntry {
                    pid,
                    slack_ns: slack,
                    is_rt,
                    active: true,
                };
                self.nr_entries += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters a task.
    pub fn unregister_task(&mut self, pid: u64) -> Result<()> {
        let idx = self.find_entry(pid).ok_or(Error::NotFound)?;
        self.entries[idx].active = false;
        self.nr_entries = self.nr_entries.saturating_sub(1);
        Ok(())
    }

    /// Sets the timer slack for a task (PR_SET_TIMERSLACK).
    pub fn set_slack(&mut self, pid: u64, slack_ns: u64) -> Result<()> {
        let idx = self.find_entry(pid).ok_or(Error::NotFound)?;
        let entry = &mut self.entries[idx];
        if entry.is_rt {
            return Err(Error::PermissionDenied);
        }
        if slack_ns > MAX_SLACK_NS {
            return Err(Error::InvalidArgument);
        }
        entry.slack_ns = if slack_ns == 0 {
            self.default_slack_ns
        } else {
            slack_ns
        };
        self.stats.set_calls += 1;
        Ok(())
    }

    /// Gets the timer slack for a task.
    pub fn get_slack(&self, pid: u64) -> Result<u64> {
        let idx = self.find_entry(pid).ok_or(Error::NotFound)?;
        Ok(self.entries[idx].slack_ns)
    }

    /// Computes the effective deadline for a timer.
    ///
    /// Returns the latest acceptable expiry (deadline + slack).
    pub fn effective_deadline(&self, pid: u64, deadline_ns: u64) -> Result<u64> {
        let idx = self.find_entry(pid).ok_or(Error::NotFound)?;
        let slack = self.entries[idx].slack_ns;
        Ok(deadline_ns.saturating_add(slack))
    }

    /// Tries to coalesce a timer into an existing group.
    pub fn try_coalesce(&mut self, deadline_ns: u64, slack_ns: u64) -> CoalesceResult {
        let soft_deadline = deadline_ns.saturating_add(slack_ns);

        for group in &mut self.groups[..self.nr_groups] {
            if !group.active {
                continue;
            }
            // Can coalesce if deadline falls within the group window.
            if deadline_ns <= group.latest_ns && soft_deadline >= group.earliest_ns {
                if deadline_ns < group.earliest_ns {
                    group.earliest_ns = deadline_ns;
                }
                if soft_deadline > group.latest_ns {
                    group.latest_ns = soft_deadline;
                }
                group.count += 1;
                self.stats.coalesced_count += 1;
                self.stats.saved_ns += slack_ns;
                return CoalesceResult::Coalesced;
            }
        }
        // Create a new group.
        if self.nr_groups < MAX_GROUPS {
            self.groups[self.nr_groups] = TimerGroup {
                earliest_ns: deadline_ns,
                latest_ns: soft_deadline,
                count: 1,
                active: true,
            };
            self.nr_groups += 1;
        }
        self.stats.standalone_count += 1;
        CoalesceResult::Standalone
    }

    /// Returns statistics.
    pub fn stats(&self) -> &SlackStats {
        &self.stats
    }

    /// Returns the number of registered tasks.
    pub fn nr_entries(&self) -> usize {
        self.nr_entries
    }

    /// Returns the system default slack.
    pub fn default_slack_ns(&self) -> u64 {
        self.default_slack_ns
    }

    // ------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------

    fn find_entry(&self, pid: u64) -> Option<usize> {
        self.entries.iter().position(|e| e.active && e.pid == pid)
    }
}

impl Default for TimerSlackManager {
    fn default() -> Self {
        Self::new()
    }
}
