// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! OOM score calculation subsystem.
//!
//! Computes out-of-memory scores for processes to determine which
//! process should be killed when the system runs critically low
//! on memory. Scores range from 0 (never kill) to 1000 (always
//! kill first), influenced by RSS, oom_score_adj, and privileges.

use oncrix_lib::{Error, Result};

/// Maximum OOM score value.
const MAX_OOM_SCORE: u64 = 1000;

/// Minimum OOM score adjustment value.
const _MIN_OOM_SCORE_ADJ: i64 = -1000;

/// Maximum OOM score adjustment value.
const _MAX_OOM_SCORE_ADJ: i64 = 1000;

/// Maximum number of tracked processes for OOM scoring.
const MAX_TRACKED_PROCS: usize = 512;

/// Process memory information used for OOM scoring.
#[derive(Clone, Copy)]
pub struct ProcessMemInfo {
    /// Process identifier.
    pid: u64,
    /// Resident set size in pages.
    rss_pages: u64,
    /// Shared memory pages.
    shared_pages: u64,
    /// Swap usage in pages.
    swap_pages: u64,
    /// Page table pages.
    pgtable_pages: u64,
    /// OOM score adjustment (-1000 to 1000).
    oom_score_adj: i64,
    /// Whether process is a kernel thread.
    is_kernel_thread: bool,
    /// Whether process has CAP_SYS_ADMIN.
    has_cap_sys_admin: bool,
}

impl ProcessMemInfo {
    /// Creates a new process memory information entry.
    pub const fn new() -> Self {
        Self {
            pid: 0,
            rss_pages: 0,
            shared_pages: 0,
            swap_pages: 0,
            pgtable_pages: 0,
            oom_score_adj: 0,
            is_kernel_thread: false,
            has_cap_sys_admin: false,
        }
    }

    /// Creates a process memory info with the given PID and RSS.
    pub const fn with_pid_rss(pid: u64, rss_pages: u64) -> Self {
        Self {
            pid,
            rss_pages,
            shared_pages: 0,
            swap_pages: 0,
            pgtable_pages: 0,
            oom_score_adj: 0,
            is_kernel_thread: false,
            has_cap_sys_admin: false,
        }
    }

    /// Returns the process identifier.
    pub const fn pid(&self) -> u64 {
        self.pid
    }

    /// Returns the total memory footprint in pages.
    pub const fn total_pages(&self) -> u64 {
        self.rss_pages + self.swap_pages + self.pgtable_pages
    }

    /// Sets the OOM score adjustment value.
    pub fn set_oom_score_adj(&mut self, adj: i64) -> Result<()> {
        if adj < -1000 || adj > 1000 {
            return Err(Error::InvalidArgument);
        }
        self.oom_score_adj = adj;
        Ok(())
    }
}

impl Default for ProcessMemInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// Computed OOM score for a process.
#[derive(Clone, Copy)]
pub struct OomScore {
    /// Process identifier.
    pid: u64,
    /// Computed score (0 to 1000).
    score: u64,
    /// Whether the process is unkillable.
    unkillable: bool,
}

impl OomScore {
    /// Creates a new OOM score entry.
    pub const fn new() -> Self {
        Self {
            pid: 0,
            score: 0,
            unkillable: false,
        }
    }

    /// Returns the process identifier.
    pub const fn pid(&self) -> u64 {
        self.pid
    }

    /// Returns the computed OOM score.
    pub const fn score(&self) -> u64 {
        self.score
    }

    /// Returns whether the process is unkillable.
    pub const fn is_unkillable(&self) -> bool {
        self.unkillable
    }
}

impl Default for OomScore {
    fn default() -> Self {
        Self::new()
    }
}

/// OOM score calculator tracking system-wide memory state.
pub struct OomScoreCalculator {
    /// Total available system pages.
    total_pages: u64,
    /// Total swap pages available.
    total_swap_pages: u64,
    /// Tracked process memory info entries.
    entries: [ProcessMemInfo; MAX_TRACKED_PROCS],
    /// Number of active entries.
    count: usize,
}

impl OomScoreCalculator {
    /// Creates a new OOM score calculator.
    pub const fn new() -> Self {
        Self {
            total_pages: 0,
            total_swap_pages: 0,
            entries: [const { ProcessMemInfo::new() }; MAX_TRACKED_PROCS],
            count: 0,
        }
    }

    /// Sets the total system memory in pages.
    pub fn set_total_pages(&mut self, pages: u64) {
        self.total_pages = pages;
    }

    /// Sets the total swap space in pages.
    pub fn set_total_swap_pages(&mut self, pages: u64) {
        self.total_swap_pages = pages;
    }

    /// Registers a process for OOM scoring.
    pub fn register_process(&mut self, info: ProcessMemInfo) -> Result<()> {
        if self.count >= MAX_TRACKED_PROCS {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = info;
        self.count += 1;
        Ok(())
    }

    /// Removes a process from OOM tracking by PID.
    pub fn unregister_process(&mut self, pid: u64) -> Result<()> {
        let pos = self.entries[..self.count].iter().position(|e| e.pid == pid);
        match pos {
            Some(idx) => {
                // Shift remaining entries
                let mut i = idx;
                while i + 1 < self.count {
                    self.entries[i] = self.entries[i + 1];
                    i += 1;
                }
                self.count -= 1;
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Computes the OOM score for a single process.
    pub fn compute_score(&self, info: &ProcessMemInfo) -> OomScore {
        // Kernel threads are never killed
        if info.is_kernel_thread {
            return OomScore {
                pid: info.pid,
                score: 0,
                unkillable: true,
            };
        }

        // oom_score_adj of -1000 means never kill
        if info.oom_score_adj == -1000 {
            return OomScore {
                pid: info.pid,
                score: 0,
                unkillable: true,
            };
        }

        let total_available = self.total_pages + self.total_swap_pages;
        if total_available == 0 {
            return OomScore {
                pid: info.pid,
                score: 0,
                unkillable: false,
            };
        }

        // Base score from memory usage proportion
        let usage = info.total_pages();
        let base_score = (usage * MAX_OOM_SCORE) / total_available;

        // Apply adjustment
        let adj_factor = (info.oom_score_adj * MAX_OOM_SCORE as i64) / 1000;
        let adjusted = base_score as i64 + adj_factor;

        // Clamp to valid range
        let final_score = if adjusted < 0 {
            0u64
        } else if (adjusted as u64) > MAX_OOM_SCORE {
            MAX_OOM_SCORE
        } else {
            adjusted as u64
        };

        // oom_score_adj of 1000 always results in max score
        let score = if info.oom_score_adj == 1000 {
            MAX_OOM_SCORE
        } else {
            final_score
        };

        OomScore {
            pid: info.pid,
            score,
            unkillable: false,
        }
    }

    /// Finds the process with the highest OOM score.
    pub fn find_worst_process(&self) -> Result<OomScore> {
        if self.count == 0 {
            return Err(Error::NotFound);
        }

        let mut worst = OomScore::new();

        for entry in &self.entries[..self.count] {
            let score = self.compute_score(entry);
            if !score.unkillable && score.score > worst.score {
                worst = score;
            }
        }

        if worst.pid == 0 && worst.score == 0 {
            return Err(Error::NotFound);
        }

        Ok(worst)
    }

    /// Returns the number of tracked processes.
    pub const fn process_count(&self) -> usize {
        self.count
    }

    /// Updates OOM score adjustment for a process.
    pub fn update_score_adj(&mut self, pid: u64, adj: i64) -> Result<()> {
        for entry in &mut self.entries[..self.count] {
            if entry.pid == pid {
                return entry.set_oom_score_adj(adj);
            }
        }
        Err(Error::NotFound)
    }
}

impl Default for OomScoreCalculator {
    fn default() -> Self {
        Self::new()
    }
}
