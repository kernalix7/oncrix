// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! OOM reaper — asynchronous memory reclamation from killed tasks.
//!
//! When the OOM killer selects a victim, the OOM reaper asynchronously
//! unmaps and frees the victim's anonymous memory. This prevents the
//! situation where a killed process holds onto memory while stuck in
//! an uninterruptible state.
//!
//! - [`ReaperState`] — victim process state
//! - [`ReaperVictim`] — a process selected for reaping
//! - [`ReaperConfig`] — reaper configuration
//! - [`ReaperStats`] — aggregate reaper statistics
//! - [`OomReaper`] — the main OOM reaper
//!
//! Reference: Linux `mm/oom_kill.c` (oom_reaper thread).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of pending victims.
const MAX_VICTIMS: usize = 32;

/// Default reaper timeout in milliseconds.
const DEFAULT_TIMEOUT_MS: u64 = 1000;

/// Maximum reap attempts per victim.
const MAX_REAP_ATTEMPTS: u32 = 10;

// -------------------------------------------------------------------
// ReaperState
// -------------------------------------------------------------------

/// Victim process state during reaping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReaperState {
    /// Pending reap.
    #[default]
    Pending,
    /// Reaping in progress.
    Reaping,
    /// Successfully reaped.
    Reaped,
    /// Reap failed (process cannot be reaped).
    Failed,
    /// Timed out waiting for process exit.
    TimedOut,
}

// -------------------------------------------------------------------
// ReaperVictim
// -------------------------------------------------------------------

/// A process selected for OOM reaping.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReaperVictim {
    /// Process ID.
    pub pid: u64,
    /// Thread group ID.
    pub tgid: u64,
    /// Memory size (in pages) at time of selection.
    pub mm_pages: u64,
    /// Pages reaped so far.
    pub pages_reaped: u64,
    /// Current state.
    pub state: ReaperState,
    /// Number of reap attempts.
    pub attempts: u32,
    /// Timestamp when victim was queued (nanoseconds).
    pub queued_ns: u64,
    /// Whether the victim's mm has been marked for reaping.
    pub mm_marked: bool,
    /// Whether this slot is active.
    pub active: bool,
}

impl ReaperVictim {
    /// Creates a new victim entry.
    pub fn new(pid: u64, tgid: u64, mm_pages: u64, queued_ns: u64) -> Self {
        Self {
            pid,
            tgid,
            mm_pages,
            pages_reaped: 0,
            state: ReaperState::Pending,
            attempts: 0,
            queued_ns,
            mm_marked: false,
            active: true,
        }
    }

    /// Returns the progress ratio (per-mille).
    pub fn progress(&self) -> u32 {
        if self.mm_pages == 0 {
            return 1000;
        }
        ((self.pages_reaped * 1000) / self.mm_pages) as u32
    }
}

// -------------------------------------------------------------------
// ReaperConfig
// -------------------------------------------------------------------

/// OOM reaper configuration.
#[derive(Debug, Clone, Copy)]
pub struct ReaperConfig {
    /// Timeout in milliseconds before giving up on a victim.
    pub timeout_ms: u64,
    /// Maximum reap attempts per victim.
    pub max_attempts: u32,
    /// Whether to reap shared mappings.
    pub reap_shared: bool,
}

impl Default for ReaperConfig {
    fn default() -> Self {
        Self {
            timeout_ms: DEFAULT_TIMEOUT_MS,
            max_attempts: MAX_REAP_ATTEMPTS,
            reap_shared: false,
        }
    }
}

// -------------------------------------------------------------------
// ReaperStats
// -------------------------------------------------------------------

/// Aggregate OOM reaper statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReaperStats {
    /// Total victims queued.
    pub victims_queued: u64,
    /// Successfully reaped.
    pub victims_reaped: u64,
    /// Failed reaps.
    pub victims_failed: u64,
    /// Timed out.
    pub victims_timed_out: u64,
    /// Total pages freed by reaper.
    pub pages_freed: u64,
    /// Total reap attempts.
    pub reap_attempts: u64,
}

impl ReaperStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// OomReaper
// -------------------------------------------------------------------

/// The OOM reaper manages asynchronous memory recovery from killed tasks.
pub struct OomReaper {
    /// Pending victims.
    victims: [ReaperVictim; MAX_VICTIMS],
    /// Number of victims queued.
    count: usize,
    /// Configuration.
    config: ReaperConfig,
    /// Statistics.
    stats: ReaperStats,
}

impl Default for OomReaper {
    fn default() -> Self {
        Self {
            victims: [ReaperVictim::default(); MAX_VICTIMS],
            count: 0,
            config: ReaperConfig::default(),
            stats: ReaperStats::default(),
        }
    }
}

impl OomReaper {
    /// Creates a new OOM reaper.
    pub fn new() -> Self {
        Self::default()
    }

    /// Queues a victim for reaping.
    pub fn queue_victim(
        &mut self,
        pid: u64,
        tgid: u64,
        mm_pages: u64,
        timestamp_ns: u64,
    ) -> Result<usize> {
        if self.count >= MAX_VICTIMS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.victims[idx] = ReaperVictim::new(pid, tgid, mm_pages, timestamp_ns);
        self.count += 1;
        self.stats.victims_queued += 1;
        Ok(idx)
    }

    /// Attempts to reap a victim's memory.
    pub fn reap(&mut self, idx: usize) -> Result<u64> {
        if idx >= self.count || !self.victims[idx].active {
            return Err(Error::NotFound);
        }

        let victim = &mut self.victims[idx];
        victim.attempts += 1;
        self.stats.reap_attempts += 1;

        if victim.attempts > self.config.max_attempts {
            victim.state = ReaperState::Failed;
            self.stats.victims_failed += 1;
            return Err(Error::Busy);
        }

        victim.state = ReaperState::Reaping;
        victim.mm_marked = true;

        // Simulate reaping: free all remaining pages.
        let freed = victim.mm_pages.saturating_sub(victim.pages_reaped);
        victim.pages_reaped = victim.mm_pages;
        victim.state = ReaperState::Reaped;

        self.stats.pages_freed += freed;
        self.stats.victims_reaped += 1;
        Ok(freed)
    }

    /// Checks for and handles timed-out victims.
    pub fn check_timeouts(&mut self, current_ns: u64) {
        let timeout_ns = self.config.timeout_ms * 1_000_000;
        for i in 0..self.count {
            if !self.victims[i].active {
                continue;
            }
            if self.victims[i].state != ReaperState::Pending
                && self.victims[i].state != ReaperState::Reaping
            {
                continue;
            }
            if current_ns.saturating_sub(self.victims[i].queued_ns) > timeout_ns {
                self.victims[i].state = ReaperState::TimedOut;
                self.stats.victims_timed_out += 1;
            }
        }
    }

    /// Returns the number of pending victims.
    pub fn pending_count(&self) -> usize {
        self.victims[..self.count]
            .iter()
            .filter(|v| v.active && v.state == ReaperState::Pending)
            .count()
    }

    /// Returns statistics.
    pub fn stats(&self) -> &ReaperStats {
        &self.stats
    }

    /// Returns a reference to a victim.
    pub fn get_victim(&self, idx: usize) -> Option<&ReaperVictim> {
        if idx < self.count && self.victims[idx].active {
            Some(&self.victims[idx])
        } else {
            None
        }
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
