// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! OOM (Out-Of-Memory) killer for the ONCRIX microkernel.
//!
//! Selects and kills processes when the system runs critically
//! low on memory, using a scoring heuristic based on resident
//! set size, swap usage, and a user-adjustable score adjustment.
//!
//! # Types
//!
//! - [`OomPolicy`] — action to take on OOM condition
//! - [`OomPriority`] — process OOM priority class
//! - [`ProcessOomInfo`] — per-process OOM accounting data
//! - [`OomVictim`] — record of an OOM kill event
//! - [`OomKiller`] — the OOM killer state machine
//! - [`OomStats`] — summary statistics

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Minimum value for `oom_score_adj`.
const _OOM_SCORE_ADJ_MIN: i32 = -1000;

/// Maximum value for `oom_score_adj`.
const _OOM_SCORE_ADJ_MAX: i32 = 1000;

/// Score adjustment that disables OOM killing for a process.
const OOM_DISABLE: i32 = -1000;

/// Maximum number of recorded OOM victims.
const MAX_OOM_VICTIMS: usize = 32;

/// Maximum number of tracked processes.
const MAX_PROCESSES: usize = 256;

/// Base value for OOM score computation.
const _OOM_SCORE_BASE: u32 = 1000;

// -------------------------------------------------------------------
// OomPolicy
// -------------------------------------------------------------------

/// Policy to apply when the system is out of memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OomPolicy {
    /// Kill the highest-scored process (default).
    #[default]
    Kill,
    /// Panic the kernel immediately.
    Panic,
    /// Retry memory reclaim before killing.
    Retry,
}

// -------------------------------------------------------------------
// OomPriority
// -------------------------------------------------------------------

/// Priority class influencing OOM victim selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OomPriority {
    /// Normal priority (default).
    #[default]
    Normal,
    /// Low priority — less likely to be killed.
    Low,
    /// High priority — more likely to be killed.
    High,
    /// Critical — kill first when under pressure.
    Critical,
}

// -------------------------------------------------------------------
// ProcessOomInfo
// -------------------------------------------------------------------

/// Per-process OOM accounting information.
#[derive(Debug, Clone, Copy)]
pub struct ProcessOomInfo {
    /// Process identifier.
    pub pid: u64,
    /// User identifier of the process owner.
    pub uid: u32,
    /// Resident set size in pages.
    pub rss_pages: u64,
    /// Swap usage in pages.
    pub swap_pages: u64,
    /// User-adjustable OOM score adjustment (-1000..=1000).
    pub oom_score_adj: i32,
    /// Computed OOM score (higher → more likely to be killed).
    pub oom_score: u32,
    /// Process name (truncated to 16 bytes).
    pub name: [u8; 16],
    /// Number of valid bytes in `name`.
    pub name_len: usize,
    /// Whether the process is unkillable (kernel thread).
    pub unkillable: bool,
    /// Whether the slot is active.
    pub active: bool,
}

impl ProcessOomInfo {
    /// Creates a zeroed, inactive `ProcessOomInfo`.
    const fn empty() -> Self {
        Self {
            pid: 0,
            uid: 0,
            rss_pages: 0,
            swap_pages: 0,
            oom_score_adj: 0,
            oom_score: 0,
            name: [0u8; 16],
            name_len: 0,
            unkillable: false,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// OomVictim
// -------------------------------------------------------------------

/// Record of an OOM kill event.
#[derive(Debug, Clone, Copy)]
pub struct OomVictim {
    /// PID of the killed process.
    pub pid: u64,
    /// OOM score at the time of killing.
    pub score: u32,
    /// Resident set size at the time of killing (pages).
    pub rss_pages: u64,
    /// Kernel timestamp of the kill in nanoseconds.
    pub timestamp_ns: u64,
}

impl OomVictim {
    /// Creates a zeroed `OomVictim`.
    const fn empty() -> Self {
        Self {
            pid: 0,
            score: 0,
            rss_pages: 0,
            timestamp_ns: 0,
        }
    }
}

// -------------------------------------------------------------------
// OomStats
// -------------------------------------------------------------------

/// Summary statistics from the OOM killer.
#[derive(Debug, Clone, Copy, Default)]
pub struct OomStats {
    /// Total number of processes killed.
    pub total_kills: u64,
    /// Timestamp of the most recent kill (nanoseconds).
    pub last_kill_ns: u64,
    /// Number of currently tracked processes.
    pub process_count: usize,
    /// Current OOM policy.
    pub policy: OomPolicy,
}

// -------------------------------------------------------------------
// OomKiller
// -------------------------------------------------------------------

/// The OOM killer: tracks processes, computes scores, and selects
/// victims when the system is critically low on memory.
pub struct OomKiller {
    /// Per-process OOM information table.
    processes: [ProcessOomInfo; MAX_PROCESSES],
    /// Number of active processes in the table.
    process_count: usize,
    /// Ring of recorded OOM victims.
    victims: [OomVictim; MAX_OOM_VICTIMS],
    /// Number of recorded victims.
    victim_count: usize,
    /// Current OOM policy.
    policy: OomPolicy,
    /// Total processes killed since boot.
    total_kills: u64,
    /// Timestamp of the last kill in nanoseconds.
    last_kill_ns: u64,
    /// Whether to panic instead of killing on OOM.
    _panic_on_oom: bool,
}

impl Default for OomKiller {
    fn default() -> Self {
        Self::new()
    }
}

impl OomKiller {
    /// Creates a new, empty `OomKiller`.
    pub const fn new() -> Self {
        Self {
            processes: [ProcessOomInfo::empty(); MAX_PROCESSES],
            process_count: 0,
            victims: [OomVictim::empty(); MAX_OOM_VICTIMS],
            victim_count: 0,
            policy: OomPolicy::Kill,
            total_kills: 0,
            last_kill_ns: 0,
            _panic_on_oom: false,
        }
    }

    /// Registers a new process with the OOM killer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the process table is full.
    /// Returns [`Error::AlreadyExists`] if `pid` is already
    /// registered.
    pub fn register_process(&mut self, pid: u64, name: &[u8], uid: u32) -> Result<()> {
        // Check for duplicate PID.
        if self.processes.iter().any(|p| p.active && p.pid == pid) {
            return Err(Error::AlreadyExists);
        }

        // Find a free slot.
        let slot = self
            .processes
            .iter_mut()
            .find(|p| !p.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = ProcessOomInfo::empty();
        slot.pid = pid;
        slot.uid = uid;
        slot.active = true;

        let copy_len = name.len().min(16);
        slot.name[..copy_len].copy_from_slice(&name[..copy_len]);
        slot.name_len = copy_len;

        self.process_count += 1;
        Ok(())
    }

    /// Unregisters a process from the OOM killer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no active process with the
    /// given `pid` exists.
    pub fn unregister_process(&mut self, pid: u64) -> Result<()> {
        let proc = self
            .processes
            .iter_mut()
            .find(|p| p.active && p.pid == pid)
            .ok_or(Error::NotFound)?;
        proc.active = false;
        self.process_count -= 1;
        Ok(())
    }

    /// Updates the resident set size and swap usage for a process.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the process is not registered.
    pub fn update_rss(&mut self, pid: u64, rss: u64, swap: u64) -> Result<()> {
        let proc = self
            .processes
            .iter_mut()
            .find(|p| p.active && p.pid == pid)
            .ok_or(Error::NotFound)?;
        proc.rss_pages = rss;
        proc.swap_pages = swap;
        Ok(())
    }

    /// Sets the OOM score adjustment for a process.
    ///
    /// The value must be in the range `-1000..=1000`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `adj` is out of range.
    /// Returns [`Error::NotFound`] if the process is not registered.
    pub fn set_oom_score_adj(&mut self, pid: u64, adj: i32) -> Result<()> {
        if !(-1000..=1000).contains(&adj) {
            return Err(Error::InvalidArgument);
        }
        let proc = self
            .processes
            .iter_mut()
            .find(|p| p.active && p.pid == pid)
            .ok_or(Error::NotFound)?;
        proc.oom_score_adj = adj;
        Ok(())
    }

    /// Recomputes OOM scores for all active processes.
    ///
    /// The score is derived from resident + swap pages, adjusted
    /// by the per-process `oom_score_adj` value.
    pub fn compute_scores(&mut self) {
        for proc in &mut self.processes {
            if !proc.active {
                continue;
            }
            let total = proc.rss_pages.saturating_add(proc.swap_pages);
            let base = if total > u64::from(u32::MAX) {
                u32::MAX
            } else {
                total as u32
            };
            let adj = proc.oom_score_adj;
            proc.oom_score = if adj >= 0 {
                base.saturating_add(adj as u32)
            } else {
                base.saturating_sub(adj.unsigned_abs())
            };
        }
    }

    /// Selects the highest-scored killable process as the OOM
    /// victim.
    ///
    /// Processes marked unkillable or with `oom_score_adj` equal
    /// to [`OOM_DISABLE`] are excluded.
    ///
    /// Returns the PID of the selected victim, or `None` if no
    /// suitable candidate exists.
    pub fn select_victim(&mut self) -> Option<u64> {
        self.compute_scores();

        let mut best_pid: Option<u64> = None;
        let mut best_score: u32 = 0;

        for proc in &self.processes {
            if !proc.active || proc.unkillable || proc.oom_score_adj == OOM_DISABLE {
                continue;
            }
            if proc.oom_score > best_score {
                best_score = proc.oom_score;
                best_pid = Some(proc.pid);
            }
        }

        best_pid
    }

    /// Selects and kills the highest-scored victim, recording the
    /// event.
    ///
    /// Returns the [`OomVictim`] record if a process was killed,
    /// or `None` if no killable candidate exists.
    pub fn kill_victim(&mut self, now_ns: u64) -> Option<OomVictim> {
        let pid = self.select_victim()?;

        // Find the process to build the victim record.
        let proc = self.processes.iter().find(|p| p.active && p.pid == pid)?;

        let victim = OomVictim {
            pid,
            score: proc.oom_score,
            rss_pages: proc.rss_pages,
            timestamp_ns: now_ns,
        };

        // Record victim in the ring buffer.
        if self.victim_count < MAX_OOM_VICTIMS {
            self.victims[self.victim_count] = victim;
            self.victim_count += 1;
        } else {
            // Overwrite oldest entry (simple ring).
            let idx = (self.total_kills as usize) % MAX_OOM_VICTIMS;
            self.victims[idx] = victim;
        }

        self.total_kills += 1;
        self.last_kill_ns = now_ns;

        // Mark process inactive.
        if let Some(p) = self.processes.iter_mut().find(|p| p.active && p.pid == pid) {
            p.active = false;
            self.process_count -= 1;
        }

        Some(victim)
    }

    /// Marks a process as unkillable (e.g. kernel thread) or
    /// killable.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the process is not
    /// registered.
    pub fn set_unkillable(&mut self, pid: u64, val: bool) -> Result<()> {
        let proc = self
            .processes
            .iter_mut()
            .find(|p| p.active && p.pid == pid)
            .ok_or(Error::NotFound)?;
        proc.unkillable = val;
        Ok(())
    }

    /// Sets the OOM policy.
    pub fn set_policy(&mut self, policy: OomPolicy) {
        self.policy = policy;
    }

    /// Returns the computed OOM score for a process.
    ///
    /// Triggers a score recomputation before returning.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the process is not
    /// registered.
    pub fn get_score(&mut self, pid: u64) -> Result<u32> {
        self.compute_scores();
        let proc = self
            .processes
            .iter()
            .find(|p| p.active && p.pid == pid)
            .ok_or(Error::NotFound)?;
        Ok(proc.oom_score)
    }

    /// Returns a slice of recorded OOM victims.
    pub fn recent_victims(&self) -> &[OomVictim] {
        &self.victims[..self.victim_count]
    }

    /// Returns summary statistics.
    pub fn stats(&self) -> OomStats {
        OomStats {
            total_kills: self.total_kills,
            last_kill_ns: self.last_kill_ns,
            process_count: self.process_count,
            policy: self.policy,
        }
    }

    /// Returns the number of active processes tracked.
    pub fn len(&self) -> usize {
        self.process_count
    }

    /// Returns `true` if no processes are tracked.
    pub fn is_empty(&self) -> bool {
        self.process_count == 0
    }
}
