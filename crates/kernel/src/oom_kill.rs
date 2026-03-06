// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! OOM killer implementation.
//!
//! Implements the out-of-memory killer that selects and kills
//! processes when the system runs critically low on memory.
//! Coordinates with the OOM score calculator to find the best
//! victim, sends SIGKILL, reclaims memory, and handles oom
//! group and cgroup-aware killing policies.

use oncrix_lib::{Error, Result};

/// Maximum number of OOM kill candidates.
const MAX_CANDIDATES: usize = 256;

/// Maximum number of OOM kill events in history.
const MAX_KILL_HISTORY: usize = 64;

/// Maximum number of OOM groups.
const MAX_OOM_GROUPS: usize = 32;

/// OOM kill reason.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OomKillReason {
    /// Global OOM — system ran out of memory.
    GlobalOom,
    /// Memory cgroup limit exceeded.
    CgroupOom,
    /// Sysrq triggered OOM kill.
    SysrqOom,
    /// OOM triggered by mmap failure.
    MmapOom,
    /// Page allocator failed.
    PageAllocFail,
}

impl OomKillReason {
    /// Returns a human-readable name for the reason.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::GlobalOom => "global-oom",
            Self::CgroupOom => "cgroup-oom",
            Self::SysrqOom => "sysrq-oom",
            Self::MmapOom => "mmap-oom",
            Self::PageAllocFail => "page-alloc-fail",
        }
    }
}

/// OOM kill policy.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OomPolicy {
    /// Kill the process with the highest OOM score.
    HighestScore,
    /// Kill the newest process first.
    NewestFirst,
    /// Kill the oldest process first.
    OldestFirst,
    /// Kill all processes in the OOM group.
    GroupKill,
}

/// An OOM kill candidate process.
#[derive(Clone, Copy)]
pub struct OomCandidate {
    /// Process identifier.
    pid: u64,
    /// OOM score (0-1000).
    oom_score: u64,
    /// Resident set size in pages.
    rss_pages: u64,
    /// Swap usage in pages.
    swap_pages: u64,
    /// Process creation time (ticks).
    start_time: u64,
    /// OOM group this process belongs to (-1 if none).
    oom_group: i32,
    /// Whether this process is unkillable (kernel/init).
    unkillable: bool,
    /// Whether this process has oom_score_adj = -1000.
    oom_protected: bool,
}

impl OomCandidate {
    /// Creates a new OOM candidate.
    pub const fn new() -> Self {
        Self {
            pid: 0,
            oom_score: 0,
            rss_pages: 0,
            swap_pages: 0,
            start_time: 0,
            oom_group: -1,
            unkillable: false,
            oom_protected: false,
        }
    }

    /// Creates a candidate with basic info.
    pub const fn with_info(pid: u64, oom_score: u64, rss_pages: u64) -> Self {
        Self {
            pid,
            oom_score,
            rss_pages,
            swap_pages: 0,
            start_time: 0,
            oom_group: -1,
            unkillable: false,
            oom_protected: false,
        }
    }

    /// Returns the process identifier.
    pub const fn pid(&self) -> u64 {
        self.pid
    }

    /// Returns the OOM score.
    pub const fn oom_score(&self) -> u64 {
        self.oom_score
    }

    /// Returns the RSS in pages.
    pub const fn rss_pages(&self) -> u64 {
        self.rss_pages
    }

    /// Returns total reclaimable pages.
    pub const fn reclaimable_pages(&self) -> u64 {
        self.rss_pages + self.swap_pages
    }

    /// Returns whether this process is killable.
    pub const fn is_killable(&self) -> bool {
        !self.unkillable && !self.oom_protected
    }
}

impl Default for OomCandidate {
    fn default() -> Self {
        Self::new()
    }
}

/// OOM kill event record.
#[derive(Clone, Copy)]
pub struct OomKillEvent {
    /// Killed process PID.
    pid: u64,
    /// OOM score at time of kill.
    oom_score: u64,
    /// Pages expected to be reclaimed.
    pages_reclaimed: u64,
    /// Kill reason.
    reason: OomKillReason,
    /// Timestamp of the kill.
    timestamp_ns: u64,
    /// Memory cgroup ID (if cgroup OOM, otherwise 0).
    cgroup_id: u64,
}

impl OomKillEvent {
    /// Creates a new empty OOM kill event.
    pub const fn new() -> Self {
        Self {
            pid: 0,
            oom_score: 0,
            pages_reclaimed: 0,
            reason: OomKillReason::GlobalOom,
            timestamp_ns: 0,
            cgroup_id: 0,
        }
    }

    /// Returns the killed process PID.
    pub const fn pid(&self) -> u64 {
        self.pid
    }

    /// Returns the OOM score at kill time.
    pub const fn oom_score(&self) -> u64 {
        self.oom_score
    }

    /// Returns pages reclaimed.
    pub const fn pages_reclaimed(&self) -> u64 {
        self.pages_reclaimed
    }

    /// Returns the kill reason.
    pub const fn reason(&self) -> OomKillReason {
        self.reason
    }

    /// Returns the kill timestamp.
    pub const fn timestamp_ns(&self) -> u64 {
        self.timestamp_ns
    }
}

impl Default for OomKillEvent {
    fn default() -> Self {
        Self::new()
    }
}

/// OOM group for collective killing.
#[derive(Clone, Copy)]
pub struct OomGroup {
    /// Group identifier.
    id: u32,
    /// Number of processes in this group.
    process_count: u32,
    /// Total RSS of all processes in the group.
    total_rss: u64,
    /// Whether group killing is enabled.
    group_kill_enabled: bool,
    /// Whether this group is active.
    active: bool,
}

impl OomGroup {
    /// Creates a new OOM group.
    pub const fn new() -> Self {
        Self {
            id: 0,
            process_count: 0,
            total_rss: 0,
            group_kill_enabled: false,
            active: false,
        }
    }

    /// Returns the group identifier.
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// Returns the process count.
    pub const fn process_count(&self) -> u32 {
        self.process_count
    }

    /// Returns the total RSS.
    pub const fn total_rss(&self) -> u64 {
        self.total_rss
    }
}

impl Default for OomGroup {
    fn default() -> Self {
        Self::new()
    }
}

/// OOM killer manager.
pub struct OomKiller {
    /// Kill candidates.
    candidates: [OomCandidate; MAX_CANDIDATES],
    /// Number of candidates.
    candidate_count: usize,
    /// Kill history.
    history: [OomKillEvent; MAX_KILL_HISTORY],
    /// History count.
    history_count: usize,
    /// OOM groups.
    groups: [OomGroup; MAX_OOM_GROUPS],
    /// Group count.
    group_count: usize,
    /// Active kill policy.
    policy: OomPolicy,
    /// Whether an OOM kill is currently in progress.
    kill_in_progress: bool,
    /// Total number of OOM kills.
    total_kills: u64,
    /// Total pages reclaimed via OOM kills.
    total_pages_reclaimed: u64,
    /// Whether to panic instead of killing.
    panic_on_oom: bool,
}

impl OomKiller {
    /// Creates a new OOM killer.
    pub const fn new() -> Self {
        Self {
            candidates: [const { OomCandidate::new() }; MAX_CANDIDATES],
            candidate_count: 0,
            history: [const { OomKillEvent::new() }; MAX_KILL_HISTORY],
            history_count: 0,
            groups: [const { OomGroup::new() }; MAX_OOM_GROUPS],
            group_count: 0,
            policy: OomPolicy::HighestScore,
            kill_in_progress: false,
            total_kills: 0,
            total_pages_reclaimed: 0,
            panic_on_oom: false,
        }
    }

    /// Sets the OOM kill policy.
    pub fn set_policy(&mut self, policy: OomPolicy) {
        self.policy = policy;
    }

    /// Sets panic-on-OOM behavior.
    pub fn set_panic_on_oom(&mut self, panic: bool) {
        self.panic_on_oom = panic;
    }

    /// Adds a candidate for OOM killing.
    pub fn add_candidate(&mut self, candidate: OomCandidate) -> Result<()> {
        if self.candidate_count >= MAX_CANDIDATES {
            return Err(Error::OutOfMemory);
        }
        self.candidates[self.candidate_count] = candidate;
        self.candidate_count += 1;
        Ok(())
    }

    /// Selects the victim based on the active policy.
    pub fn select_victim(&self) -> Result<&OomCandidate> {
        if self.candidate_count == 0 {
            return Err(Error::NotFound);
        }
        let mut best_idx = None;

        for i in 0..self.candidate_count {
            if !self.candidates[i].is_killable() {
                continue;
            }
            match best_idx {
                None => best_idx = Some(i),
                Some(prev) => {
                    let is_better = match self.policy {
                        OomPolicy::HighestScore => {
                            self.candidates[i].oom_score > self.candidates[prev].oom_score
                        }
                        OomPolicy::NewestFirst => {
                            self.candidates[i].start_time > self.candidates[prev].start_time
                        }
                        OomPolicy::OldestFirst => {
                            self.candidates[i].start_time < self.candidates[prev].start_time
                        }
                        OomPolicy::GroupKill => {
                            self.candidates[i].oom_score > self.candidates[prev].oom_score
                        }
                    };
                    if is_better {
                        best_idx = Some(i);
                    }
                }
            }
        }
        best_idx.map(|i| &self.candidates[i]).ok_or(Error::NotFound)
    }

    /// Records an OOM kill event.
    pub fn record_kill(
        &mut self,
        pid: u64,
        oom_score: u64,
        pages: u64,
        reason: OomKillReason,
        now_ns: u64,
    ) -> Result<()> {
        if self.history_count >= MAX_KILL_HISTORY {
            // Overwrite oldest
            let idx = self.history_count % MAX_KILL_HISTORY;
            self.history[idx] = OomKillEvent {
                pid,
                oom_score,
                pages_reclaimed: pages,
                reason,
                timestamp_ns: now_ns,
                cgroup_id: 0,
            };
        } else {
            self.history[self.history_count] = OomKillEvent {
                pid,
                oom_score,
                pages_reclaimed: pages,
                reason,
                timestamp_ns: now_ns,
                cgroup_id: 0,
            };
        }
        self.history_count += 1;
        self.total_kills += 1;
        self.total_pages_reclaimed += pages;
        Ok(())
    }

    /// Clears all candidates.
    pub fn clear_candidates(&mut self) {
        self.candidate_count = 0;
    }

    /// Creates an OOM group.
    pub fn create_group(&mut self) -> Result<u32> {
        if self.group_count >= MAX_OOM_GROUPS {
            return Err(Error::OutOfMemory);
        }
        let id = self.group_count as u32;
        self.groups[self.group_count].id = id;
        self.groups[self.group_count].active = true;
        self.group_count += 1;
        Ok(id)
    }

    /// Returns the total number of OOM kills.
    pub const fn total_kills(&self) -> u64 {
        self.total_kills
    }

    /// Returns total pages reclaimed.
    pub const fn total_pages_reclaimed(&self) -> u64 {
        self.total_pages_reclaimed
    }

    /// Returns the number of candidates.
    pub const fn candidate_count(&self) -> usize {
        self.candidate_count
    }

    /// Returns the active policy.
    pub const fn policy(&self) -> OomPolicy {
        self.policy
    }

    /// Returns whether panic-on-OOM is enabled.
    pub const fn panic_on_oom(&self) -> bool {
        self.panic_on_oom
    }
}

impl Default for OomKiller {
    fn default() -> Self {
        Self::new()
    }
}
