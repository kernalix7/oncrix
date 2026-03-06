// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! OOM score calculation.
//!
//! Computes the out-of-memory (OOM) score for each process, used by
//! the OOM killer to select which process to terminate when the
//! system runs critically low on memory.
//!
//! # Scoring Algorithm
//!
//! The base score is proportional to a process's RSS (Resident Set
//! Size) relative to total system memory. This is then adjusted by:
//! - `oom_score_adj` (-1000..+1000), a user-tunable knob
//! - Swap usage contribution
//! - Page cache usage
//! - Child process memory (optional aggregation)
//! - cgroup limits (if applicable)
//!
//! A score of 0 means the process cannot be killed. A score of 1000
//! means the process is the prime candidate.
//!
//! # Types
//!
//! - [`OomScoreAdj`] — validated `oom_score_adj` value
//! - [`ProcessMemInfo`] — per-process memory consumption data
//! - [`OomScoreInput`] — all inputs to the score function
//! - [`OomScoreResult`] — computed score with breakdown
//! - [`OomScoreConfig`] — scoring configuration knobs
//! - [`OomScoreEntry`] — cached score for one process
//! - [`OomScoreBoard`] — scoreboard for all processes
//! - [`OomScoreStats`] — summary statistics
//!
//! Reference: Linux `mm/oom_kill.c` (`oom_badness()`).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Minimum oom_score_adj value.
pub const OOM_SCORE_ADJ_MIN: i32 = -1000;

/// Maximum oom_score_adj value.
pub const OOM_SCORE_ADJ_MAX: i32 = 1000;

/// Score that completely disables OOM killing for a process.
pub const OOM_SCORE_DISABLE: i32 = -1000;

/// Maximum computed score.
const MAX_SCORE: u32 = 1000;

/// Maximum number of tracked processes.
const MAX_PROCESSES: usize = 512;

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Weight for swap usage in score (percentage of base).
const SWAP_WEIGHT_PCT: u32 = 50;

/// Weight for page cache usage (percentage of base).
const CACHE_WEIGHT_PCT: u32 = 20;

/// Maximum children to aggregate.
const MAX_CHILDREN: usize = 32;

/// Score history depth per process.
const SCORE_HISTORY: usize = 8;

// -------------------------------------------------------------------
// OomScoreAdj
// -------------------------------------------------------------------

/// Validated `oom_score_adj` value in the range [-1000, +1000].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct OomScoreAdj(i32);

impl OomScoreAdj {
    /// Creates a new score adjustment, clamped to valid range.
    pub const fn new(val: i32) -> Self {
        if val < OOM_SCORE_ADJ_MIN {
            Self(OOM_SCORE_ADJ_MIN)
        } else if val > OOM_SCORE_ADJ_MAX {
            Self(OOM_SCORE_ADJ_MAX)
        } else {
            Self(val)
        }
    }

    /// Returns the raw value.
    pub const fn value(self) -> i32 {
        self.0
    }

    /// Returns true if this adjustment disables OOM killing.
    pub const fn is_disabled(self) -> bool {
        self.0 == OOM_SCORE_DISABLE
    }

    /// Returns true if the adjustment increases kill likelihood.
    pub const fn is_positive(self) -> bool {
        self.0 > 0
    }

    /// Returns true if the adjustment decreases kill likelihood.
    pub const fn is_negative(self) -> bool {
        self.0 < 0
    }
}

impl Default for OomScoreAdj {
    fn default() -> Self {
        Self(0)
    }
}

// -------------------------------------------------------------------
// ProcessMemInfo
// -------------------------------------------------------------------

/// Per-process memory consumption data.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessMemInfo {
    /// Resident set size in pages.
    pub rss_pages: u64,
    /// Swap usage in pages.
    pub swap_pages: u64,
    /// Page cache pages attributed to this process.
    pub cache_pages: u64,
    /// Shared memory pages.
    pub shared_pages: u64,
    /// Stack size in pages.
    pub stack_pages: u64,
    /// Total virtual memory in pages.
    pub vm_pages: u64,
    /// Locked (mlock) pages.
    pub locked_pages: u64,
}

impl ProcessMemInfo {
    /// Returns the total physical memory footprint in pages.
    pub const fn total_physical(&self) -> u64 {
        self.rss_pages + self.swap_pages
    }

    /// Returns the RSS in bytes.
    pub const fn rss_bytes(&self) -> u64 {
        self.rss_pages * PAGE_SIZE
    }
}

// -------------------------------------------------------------------
// OomScoreInput
// -------------------------------------------------------------------

/// All inputs needed to compute an OOM score.
#[derive(Debug, Clone, Copy)]
pub struct OomScoreInput {
    /// Process PID.
    pub pid: u32,
    /// Memory information.
    pub mem: ProcessMemInfo,
    /// User-set oom_score_adj.
    pub adj: OomScoreAdj,
    /// Total system memory in pages.
    pub total_ram: u64,
    /// Total system swap in pages.
    pub total_swap: u64,
    /// Whether to include child memory.
    pub include_children: bool,
    /// Aggregate child RSS in pages.
    pub child_rss: u64,
    /// cgroup memory limit in pages (0 = no limit).
    pub cgroup_limit: u64,
    /// Whether the process is a kernel thread.
    pub is_kernel_thread: bool,
    /// Whether the process holds a privileged capability.
    pub is_privileged: bool,
}

impl Default for OomScoreInput {
    fn default() -> Self {
        Self {
            pid: 0,
            mem: ProcessMemInfo::default(),
            adj: OomScoreAdj::default(),
            total_ram: 0,
            total_swap: 0,
            include_children: false,
            child_rss: 0,
            cgroup_limit: 0,
            is_kernel_thread: false,
            is_privileged: false,
        }
    }
}

// -------------------------------------------------------------------
// OomScoreResult
// -------------------------------------------------------------------

/// Computed OOM score with a breakdown of contributing factors.
#[derive(Debug, Clone, Copy, Default)]
pub struct OomScoreResult {
    /// Final score (0..1000).
    pub score: u32,
    /// Base score from RSS proportion.
    pub base_score: u32,
    /// Adjustment from oom_score_adj.
    pub adj_delta: i32,
    /// Contribution from swap usage.
    pub swap_contribution: u32,
    /// Contribution from page cache.
    pub cache_contribution: u32,
    /// Contribution from child memory.
    pub child_contribution: u32,
    /// Whether the process is immune (score == 0).
    pub immune: bool,
    /// Reason for immunity (if immune).
    pub immune_reason: ImmunityReason,
}

/// Reason a process is immune to OOM killing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ImmunityReason {
    /// Not immune.
    #[default]
    None,
    /// oom_score_adj is -1000.
    ScoreAdjDisabled,
    /// Process is a kernel thread.
    KernelThread,
    /// Process is init (PID 1).
    InitProcess,
}

// -------------------------------------------------------------------
// OomScoreConfig
// -------------------------------------------------------------------

/// Configuration knobs for OOM score calculation.
#[derive(Debug, Clone, Copy)]
pub struct OomScoreConfig {
    /// Whether to factor in swap usage.
    pub count_swap: bool,
    /// Whether to factor in page cache.
    pub count_cache: bool,
    /// Swap weight as percentage of base score.
    pub swap_weight: u32,
    /// Cache weight as percentage of base score.
    pub cache_weight: u32,
    /// Whether to aggregate child memory.
    pub aggregate_children: bool,
    /// Privileged process score discount (subtracted from score).
    pub privileged_discount: u32,
    /// Whether init (PID 1) is immune.
    pub init_immune: bool,
}

impl Default for OomScoreConfig {
    fn default() -> Self {
        Self {
            count_swap: true,
            count_cache: true,
            swap_weight: SWAP_WEIGHT_PCT,
            cache_weight: CACHE_WEIGHT_PCT,
            aggregate_children: true,
            privileged_discount: 30,
            init_immune: true,
        }
    }
}

// -------------------------------------------------------------------
// OomScoreEntry
// -------------------------------------------------------------------

/// Cached OOM score for one process.
#[derive(Clone, Copy)]
pub struct OomScoreEntry {
    /// Process PID.
    pub pid: u32,
    /// Whether this entry is active.
    pub active: bool,
    /// Current score.
    pub score: u32,
    /// Score adjustment.
    pub adj: OomScoreAdj,
    /// Memory information at last computation.
    pub mem: ProcessMemInfo,
    /// Last computed result.
    pub result: OomScoreResult,
    /// Score history (ring buffer).
    pub history: [u32; SCORE_HISTORY],
    /// History write index.
    pub history_idx: usize,
    /// Number of valid history entries.
    pub history_len: usize,
    /// Number of times this process was selected as victim.
    pub kill_count: u32,
}

impl OomScoreEntry {
    /// Creates an empty entry.
    const fn empty() -> Self {
        Self {
            pid: 0,
            active: false,
            score: 0,
            adj: OomScoreAdj(0),
            mem: ProcessMemInfo {
                rss_pages: 0,
                swap_pages: 0,
                cache_pages: 0,
                shared_pages: 0,
                stack_pages: 0,
                vm_pages: 0,
                locked_pages: 0,
            },
            result: OomScoreResult {
                score: 0,
                base_score: 0,
                adj_delta: 0,
                swap_contribution: 0,
                cache_contribution: 0,
                child_contribution: 0,
                immune: false,
                immune_reason: ImmunityReason::None,
            },
            history: [0; SCORE_HISTORY],
            history_idx: 0,
            history_len: 0,
            kill_count: 0,
        }
    }

    /// Records the current score in history.
    fn record_score(&mut self, score: u32) {
        self.history[self.history_idx] = score;
        self.history_idx = (self.history_idx + 1) % SCORE_HISTORY;
        if self.history_len < SCORE_HISTORY {
            self.history_len += 1;
        }
    }

    /// Returns the average score from history.
    pub fn avg_score(&self) -> u32 {
        if self.history_len == 0 {
            return 0;
        }
        let sum: u32 = self.history[..self.history_len].iter().sum();
        sum / self.history_len as u32
    }
}

impl Default for OomScoreEntry {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// OomScoreStats
// -------------------------------------------------------------------

/// Summary statistics for the OOM score board.
#[derive(Debug, Clone, Copy, Default)]
pub struct OomScoreStats {
    /// Total score computations.
    pub total_computations: u64,
    /// Total victim selections.
    pub total_victim_selections: u64,
    /// Number of active processes.
    pub active_processes: u32,
    /// Number of immune processes.
    pub immune_processes: u32,
    /// Highest score currently.
    pub highest_score: u32,
    /// PID with the highest score.
    pub highest_score_pid: u32,
}

// -------------------------------------------------------------------
// OomScoreBoard
// -------------------------------------------------------------------

/// Scoreboard tracking OOM scores for all processes.
pub struct OomScoreBoard {
    /// Per-process entries.
    entries: [OomScoreEntry; MAX_PROCESSES],
    /// Configuration.
    config: OomScoreConfig,
    /// Statistics.
    stats: OomScoreStats,
    /// Total system RAM in pages.
    total_ram: u64,
    /// Total system swap in pages.
    total_swap: u64,
}

impl OomScoreBoard {
    /// Creates a new scoreboard.
    pub fn new(total_ram: u64, total_swap: u64) -> Self {
        Self {
            entries: [OomScoreEntry::empty(); MAX_PROCESSES],
            config: OomScoreConfig::default(),
            stats: OomScoreStats::default(),
            total_ram,
            total_swap,
        }
    }

    /// Registers a process.
    pub fn register(&mut self, pid: u32, adj: OomScoreAdj) -> Result<usize> {
        // Check for duplicates.
        for i in 0..MAX_PROCESSES {
            if self.entries[i].active && self.entries[i].pid == pid {
                return Err(Error::AlreadyExists);
            }
        }
        let idx = self.find_free_slot()?;
        self.entries[idx] = OomScoreEntry::empty();
        self.entries[idx].pid = pid;
        self.entries[idx].adj = adj;
        self.entries[idx].active = true;
        self.stats.active_processes += 1;
        Ok(idx)
    }

    /// Unregisters a process.
    pub fn unregister(&mut self, pid: u32) -> Result<()> {
        let idx = self.find_by_pid(pid)?;
        self.entries[idx] = OomScoreEntry::empty();
        self.stats.active_processes = self.stats.active_processes.saturating_sub(1);
        Ok(())
    }

    /// Updates the memory info for a process and recomputes its
    /// score.
    pub fn update(&mut self, pid: u32, mem: ProcessMemInfo) -> Result<OomScoreResult> {
        let idx = self.find_by_pid(pid)?;
        self.entries[idx].mem = mem;
        let input = OomScoreInput {
            pid,
            mem,
            adj: self.entries[idx].adj,
            total_ram: self.total_ram,
            total_swap: self.total_swap,
            include_children: false,
            child_rss: 0,
            cgroup_limit: 0,
            is_kernel_thread: false,
            is_privileged: false,
        };
        let result = self.compute_score(&input);
        self.entries[idx].score = result.score;
        self.entries[idx].result = result;
        self.entries[idx].record_score(result.score);
        self.stats.total_computations += 1;
        self.update_highest();
        Ok(result)
    }

    /// Updates the memory info with full input (including children,
    /// cgroup, etc.).
    pub fn update_full(&mut self, input: &OomScoreInput) -> Result<OomScoreResult> {
        let idx = self.find_by_pid(input.pid)?;
        self.entries[idx].mem = input.mem;
        self.entries[idx].adj = input.adj;
        let result = self.compute_score(input);
        self.entries[idx].score = result.score;
        self.entries[idx].result = result;
        self.entries[idx].record_score(result.score);
        self.stats.total_computations += 1;
        self.update_highest();
        Ok(result)
    }

    /// Sets the oom_score_adj for a process.
    pub fn set_adj(&mut self, pid: u32, adj: OomScoreAdj) -> Result<()> {
        let idx = self.find_by_pid(pid)?;
        self.entries[idx].adj = adj;
        Ok(())
    }

    /// Returns the current score for a process.
    pub fn get_score(&self, pid: u32) -> Result<u32> {
        let idx = self.find_by_pid(pid)?;
        Ok(self.entries[idx].score)
    }

    /// Returns the full score result for a process.
    pub fn get_result(&self, pid: u32) -> Result<OomScoreResult> {
        let idx = self.find_by_pid(pid)?;
        Ok(self.entries[idx].result)
    }

    /// Selects the process with the highest score as the OOM victim.
    ///
    /// Returns `(pid, score)` of the victim, or `None` if all
    /// processes are immune.
    pub fn select_victim(&mut self) -> Option<(u32, u32)> {
        let mut best_pid = 0u32;
        let mut best_score = 0u32;
        let mut best_idx = None;
        for i in 0..MAX_PROCESSES {
            if !self.entries[i].active {
                continue;
            }
            if self.entries[i].result.immune {
                continue;
            }
            if self.entries[i].score > best_score {
                best_score = self.entries[i].score;
                best_pid = self.entries[i].pid;
                best_idx = Some(i);
            }
        }
        if let Some(idx) = best_idx {
            self.entries[idx].kill_count += 1;
            self.stats.total_victim_selections += 1;
            Some((best_pid, best_score))
        } else {
            None
        }
    }

    /// Recomputes scores for all registered processes.
    pub fn recompute_all(&mut self) {
        for i in 0..MAX_PROCESSES {
            if !self.entries[i].active {
                continue;
            }
            let input = OomScoreInput {
                pid: self.entries[i].pid,
                mem: self.entries[i].mem,
                adj: self.entries[i].adj,
                total_ram: self.total_ram,
                total_swap: self.total_swap,
                include_children: false,
                child_rss: 0,
                cgroup_limit: 0,
                is_kernel_thread: false,
                is_privileged: false,
            };
            let result = self.compute_score(&input);
            self.entries[i].score = result.score;
            self.entries[i].result = result;
            self.entries[i].record_score(result.score);
            self.stats.total_computations += 1;
        }
        self.update_highest();
    }

    /// Updates the global configuration.
    pub fn set_config(&mut self, config: OomScoreConfig) {
        self.config = config;
    }

    /// Returns the configuration.
    pub const fn config(&self) -> &OomScoreConfig {
        &self.config
    }

    /// Updates system memory totals.
    pub fn set_system_memory(&mut self, total_ram: u64, total_swap: u64) {
        self.total_ram = total_ram;
        self.total_swap = total_swap;
    }

    /// Returns statistics.
    pub const fn stats(&self) -> &OomScoreStats {
        &self.stats
    }

    /// Returns the entry for a process.
    pub fn entry(&self, pid: u32) -> Result<&OomScoreEntry> {
        let idx = self.find_by_pid(pid)?;
        Ok(&self.entries[idx])
    }

    /// Resets all state.
    pub fn reset(&mut self) {
        let ram = self.total_ram;
        let swap = self.total_swap;
        *self = Self::new(ram, swap);
    }

    // ---------------------------------------------------------------
    // Core scoring algorithm
    // ---------------------------------------------------------------

    /// Computes the OOM score from the given input.
    ///
    /// This implements the `oom_badness()` algorithm:
    /// 1. Check immunity conditions.
    /// 2. Compute base score from RSS / total_ram.
    /// 3. Add swap and cache contributions.
    /// 4. Add child memory contribution.
    /// 5. Apply oom_score_adj.
    /// 6. Apply cgroup scaling.
    /// 7. Clamp to [0, MAX_SCORE].
    fn compute_score(&self, input: &OomScoreInput) -> OomScoreResult {
        let mut result = OomScoreResult::default();
        // Step 1: immunity checks.
        if input.adj.is_disabled() {
            result.immune = true;
            result.immune_reason = ImmunityReason::ScoreAdjDisabled;
            return result;
        }
        if input.is_kernel_thread {
            result.immune = true;
            result.immune_reason = ImmunityReason::KernelThread;
            return result;
        }
        if input.pid == 1 && self.config.init_immune {
            result.immune = true;
            result.immune_reason = ImmunityReason::InitProcess;
            return result;
        }
        let total_available = input.total_ram + input.total_swap;
        if total_available == 0 {
            return result;
        }
        // Step 2: base score from RSS.
        let rss = input.mem.rss_pages;
        result.base_score = ((rss * MAX_SCORE as u64) / total_available) as u32;
        let mut score = result.base_score as i64;
        // Step 3: swap contribution.
        if self.config.count_swap && input.mem.swap_pages > 0 {
            let swap_score = ((input.mem.swap_pages * MAX_SCORE as u64) / total_available) as u32;
            let weighted = (swap_score as u64 * self.config.swap_weight as u64 / 100) as u32;
            result.swap_contribution = weighted;
            score += weighted as i64;
        }
        // Step 4: cache contribution.
        if self.config.count_cache && input.mem.cache_pages > 0 {
            let cache_score = ((input.mem.cache_pages * MAX_SCORE as u64) / total_available) as u32;
            let weighted = (cache_score as u64 * self.config.cache_weight as u64 / 100) as u32;
            result.cache_contribution = weighted;
            score += weighted as i64;
        }
        // Step 5: child contribution.
        if self.config.aggregate_children && input.include_children && input.child_rss > 0 {
            let child_score = ((input.child_rss * MAX_SCORE as u64) / total_available) as u32;
            result.child_contribution = child_score;
            score += child_score as i64;
        }
        // Step 6: apply oom_score_adj.
        let adj_val = input.adj.value();
        let adj_scaled = (adj_val as i64 * MAX_SCORE as i64) / OOM_SCORE_ADJ_MAX as i64;
        result.adj_delta = adj_scaled as i32;
        score += adj_scaled;
        // Step 7: privileged discount.
        if input.is_privileged {
            score -= self.config.privileged_discount as i64;
        }
        // Step 8: cgroup scaling.
        if input.cgroup_limit > 0 && input.cgroup_limit < total_available {
            score = score * input.cgroup_limit as i64 / total_available as i64;
        }
        // Clamp.
        result.score = if score <= 0 {
            0
        } else if score > MAX_SCORE as i64 {
            MAX_SCORE
        } else {
            score as u32
        };
        result
    }

    // ---------------------------------------------------------------
    // Private helpers
    // ---------------------------------------------------------------

    fn find_free_slot(&self) -> Result<usize> {
        for i in 0..MAX_PROCESSES {
            if !self.entries[i].active {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    fn find_by_pid(&self, pid: u32) -> Result<usize> {
        for i in 0..MAX_PROCESSES {
            if self.entries[i].active && self.entries[i].pid == pid {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    fn update_highest(&mut self) {
        let mut highest = 0u32;
        let mut pid = 0u32;
        let mut immune_count = 0u32;
        for i in 0..MAX_PROCESSES {
            if !self.entries[i].active {
                continue;
            }
            if self.entries[i].result.immune {
                immune_count += 1;
                continue;
            }
            if self.entries[i].score > highest {
                highest = self.entries[i].score;
                pid = self.entries[i].pid;
            }
        }
        self.stats.highest_score = highest;
        self.stats.highest_score_pid = pid;
        self.stats.immune_processes = immune_count;
    }
}

impl Default for OomScoreBoard {
    fn default() -> Self {
        Self::new(0, 0)
    }
}
