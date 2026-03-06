// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! OOM killer cgroup integration.
//!
//! Provides the interface between the OOM killer and the memory cgroup
//! (memcg) hierarchy. When an out-of-memory condition is detected inside
//! a cgroup, the killer uses this module to:
//!
//! 1. Identify the cgroup that is over its memory limit.
//! 2. Select the best victim process within that cgroup.
//! 3. Record kill events and update per-cgroup OOM statistics.
//!
//! # Architecture
//!
//! The module mirrors the Linux cgroup OOM path (`mm/memcontrol.c`,
//! `mm/oom_kill.c`). Cgroups are arranged in a tree; an OOM in a leaf
//! cgroup propagates upward until a cgroup with an explicit memory limit
//! is found. That cgroup's processes are then candidates for the kill.
//!
//! # Key Types
//!
//! - [`CgroupId`] — opaque identifier for a memory cgroup
//! - [`CgroupOomPolicy`] — per-cgroup kill policy knobs
//! - [`CgroupOomEvent`] — record of one OOM kill inside a cgroup
//! - [`CgroupMemInfo`] — memory usage snapshot for a cgroup
//! - [`OomCgroupEntry`] — registry entry for one tracked cgroup
//! - [`OomCgroupKiller`] — the main cgroup-aware OOM dispatcher
//!
//! Reference: Linux `mm/memcontrol.c` (`mem_cgroup_oom()`),
//! `Documentation/admin-guide/cgroup-v2.rst`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of cgroups tracked by the OOM killer.
const MAX_CGROUPS: usize = 256;

/// Maximum number of processes per cgroup visible to the killer.
const MAX_PROCESSES_PER_CGROUP: usize = 128;

/// Maximum depth of the cgroup tree.
const MAX_CGROUP_DEPTH: usize = 16;

/// Maximum number of OOM kill events recorded per cgroup.
const MAX_OOM_EVENTS: usize = 32;

/// Score threshold below which a process is never killed (adj = -1000).
const OOM_SCORE_ADJ_MIN: i32 = -1000;

// -------------------------------------------------------------------
// CgroupId
// -------------------------------------------------------------------

/// Opaque, unique identifier for a memory cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct CgroupId(pub u32);

impl CgroupId {
    /// The root cgroup id (always exists).
    pub const ROOT: CgroupId = CgroupId(0);

    /// Return `true` if this is the root cgroup.
    pub const fn is_root(self) -> bool {
        self.0 == 0
    }

    /// Return the raw ID.
    pub const fn raw(self) -> u32 {
        self.0
    }
}

// -------------------------------------------------------------------
// CgroupOomPolicy
// -------------------------------------------------------------------

/// Per-cgroup OOM kill policy knobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CgroupOomPolicy {
    /// When `true`, the cgroup kills processes inside itself on OOM
    /// rather than propagating to the parent.
    pub kill_on_oom: bool,
    /// When `true`, kill the whole process group if one process is killed.
    pub kill_process_group: bool,
    /// Additional score adjustment applied to all processes in this
    /// cgroup (-1000..+1000).
    pub score_adj_bias: i32,
    /// Maximum number of times OOM kill is allowed before the cgroup
    /// is disabled (0 = unlimited).
    pub kill_limit: u32,
}

impl Default for CgroupOomPolicy {
    fn default() -> Self {
        CgroupOomPolicy {
            kill_on_oom: true,
            kill_process_group: false,
            score_adj_bias: 0,
            kill_limit: 0,
        }
    }
}

// -------------------------------------------------------------------
// CgroupMemInfo
// -------------------------------------------------------------------

/// Memory usage snapshot for a single cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CgroupMemInfo {
    /// Current anonymous memory usage in bytes.
    pub anon_bytes: u64,
    /// Current file-backed memory usage in bytes.
    pub file_bytes: u64,
    /// Current kernel memory usage in bytes.
    pub kernel_bytes: u64,
    /// Current swap usage in bytes.
    pub swap_bytes: u64,
    /// Configured memory limit in bytes (0 = unlimited).
    pub limit_bytes: u64,
    /// Configured memory+swap limit in bytes (0 = unlimited).
    pub memsw_limit_bytes: u64,
}

impl CgroupMemInfo {
    /// Return the total RSS (anon + file) in bytes.
    pub const fn total_rss(self) -> u64 {
        self.anon_bytes + self.file_bytes
    }

    /// Return the total usage (anon + file + kernel + swap) in bytes.
    pub const fn total_usage(self) -> u64 {
        self.anon_bytes + self.file_bytes + self.kernel_bytes + self.swap_bytes
    }

    /// Return `true` if the cgroup has exceeded its memory limit.
    pub const fn is_over_limit(self) -> bool {
        self.limit_bytes > 0 && self.total_usage() > self.limit_bytes
    }

    /// Return `true` if the cgroup has exceeded its memory+swap limit.
    pub const fn is_over_memsw_limit(self) -> bool {
        self.memsw_limit_bytes > 0
            && (self.total_usage() + self.swap_bytes) > self.memsw_limit_bytes
    }
}

// -------------------------------------------------------------------
// CgroupOomEvent
// -------------------------------------------------------------------

/// Record of one OOM kill event inside a cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CgroupOomEvent {
    /// Cgroup in which the OOM was triggered.
    pub cgroup_id: CgroupId,
    /// PID of the killed process.
    pub victim_pid: u32,
    /// OOM score of the victim at kill time.
    pub victim_score: u32,
    /// Memory freed estimate (RSS of the killed process).
    pub freed_bytes: u64,
    /// Whether the kill was successful (process found and signalled).
    pub kill_ok: bool,
    /// Serial number for ordering events.
    pub seq: u64,
}

// -------------------------------------------------------------------
// ProcessEntry
// -------------------------------------------------------------------

/// A process visible to the cgroup OOM killer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProcessEntry {
    /// Process ID.
    pub pid: u32,
    /// OOM score adjustment (-1000..+1000).
    pub oom_score_adj: i32,
    /// Estimated RSS in bytes.
    pub rss_bytes: u64,
    /// Whether this process can be killed (not unkillable).
    pub killable: bool,
}

impl ProcessEntry {
    /// Compute the effective OOM score for this process.
    pub fn effective_score(&self, total_mem_bytes: u64) -> u32 {
        if self.oom_score_adj <= OOM_SCORE_ADJ_MIN || !self.killable {
            return 0;
        }
        if total_mem_bytes == 0 {
            return 0;
        }
        let rss_pages = self.rss_bytes / 4096;
        let total_pages = total_mem_bytes / 4096;
        let base = if total_pages > 0 {
            (rss_pages * 1000 / total_pages) as i64
        } else {
            0
        };
        let adj = self.oom_score_adj as i64;
        (base + adj).clamp(0, 2000) as u32
    }
}

// -------------------------------------------------------------------
// OomCgroupEntry
// -------------------------------------------------------------------

/// Registry entry for one tracked memory cgroup.
pub struct OomCgroupEntry {
    /// This cgroup's ID.
    pub id: CgroupId,
    /// Parent cgroup ID (ROOT if this is the root).
    pub parent_id: CgroupId,
    /// Depth in the cgroup tree (root = 0).
    pub depth: u32,
    /// Policy knobs.
    pub policy: CgroupOomPolicy,
    /// Current memory usage snapshot.
    pub mem_info: CgroupMemInfo,
    /// Processes in this cgroup.
    processes: [ProcessEntry; MAX_PROCESSES_PER_CGROUP],
    /// Number of valid process entries.
    process_count: usize,
    /// Recent OOM kill events.
    events: [CgroupOomEvent; MAX_OOM_EVENTS],
    /// Number of valid event entries.
    event_count: usize,
    /// Total OOM kills ever triggered in this cgroup.
    pub total_oom_kills: u64,
    /// Whether this entry is occupied.
    occupied: bool,
}

impl OomCgroupEntry {
    const fn empty() -> Self {
        OomCgroupEntry {
            id: CgroupId(0),
            parent_id: CgroupId(0),
            depth: 0,
            policy: CgroupOomPolicy {
                kill_on_oom: true,
                kill_process_group: false,
                score_adj_bias: 0,
                kill_limit: 0,
            },
            mem_info: CgroupMemInfo {
                anon_bytes: 0,
                file_bytes: 0,
                kernel_bytes: 0,
                swap_bytes: 0,
                limit_bytes: 0,
                memsw_limit_bytes: 0,
            },
            processes: [const {
                ProcessEntry {
                    pid: 0,
                    oom_score_adj: 0,
                    rss_bytes: 0,
                    killable: false,
                }
            }; MAX_PROCESSES_PER_CGROUP],
            process_count: 0,
            events: [const {
                CgroupOomEvent {
                    cgroup_id: CgroupId(0),
                    victim_pid: 0,
                    victim_score: 0,
                    freed_bytes: 0,
                    kill_ok: false,
                    seq: 0,
                }
            }; MAX_OOM_EVENTS],
            event_count: 0,
            total_oom_kills: 0,
            occupied: false,
        }
    }

    /// Add a process to this cgroup's process table.
    pub fn add_process(&mut self, entry: ProcessEntry) -> Result<()> {
        if self.process_count >= MAX_PROCESSES_PER_CGROUP {
            return Err(Error::OutOfMemory);
        }
        self.processes[self.process_count] = entry;
        self.process_count += 1;
        Ok(())
    }

    /// Remove a process by PID.
    pub fn remove_process(&mut self, pid: u32) -> bool {
        for i in 0..self.process_count {
            if self.processes[i].pid == pid {
                self.processes[i] = self.processes[self.process_count - 1];
                self.process_count -= 1;
                return true;
            }
        }
        false
    }

    /// Select the best victim process (highest effective score).
    pub fn select_victim(&self, total_mem_bytes: u64) -> Option<ProcessEntry> {
        let mut best: Option<ProcessEntry> = None;
        let mut best_score = 0u32;
        for i in 0..self.process_count {
            let p = self.processes[i];
            let score = p.effective_score(total_mem_bytes);
            if score > best_score {
                best_score = score;
                best = Some(p);
            }
        }
        best
    }

    /// Record an OOM kill event.
    pub fn record_event(&mut self, event: CgroupOomEvent) {
        if self.event_count < MAX_OOM_EVENTS {
            self.events[self.event_count] = event;
            self.event_count += 1;
        } else {
            let count = self.event_count;
            for i in 1..count {
                self.events[i - 1] = self.events[i];
            }
            self.events[self.event_count - 1] = event;
        }
        self.total_oom_kills += 1;
    }

    /// Return recent OOM events.
    pub fn events(&self) -> &[CgroupOomEvent] {
        &self.events[..self.event_count]
    }

    /// Return registered process entries.
    pub fn processes(&self) -> &[ProcessEntry] {
        &self.processes[..self.process_count]
    }
}

// -------------------------------------------------------------------
// OomCgroupStats
// -------------------------------------------------------------------

/// Aggregate statistics for the cgroup OOM subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OomCgroupStats {
    /// Number of registered cgroups.
    pub cgroup_count: u32,
    /// Total OOM events dispatched across all cgroups.
    pub total_oom_events: u64,
    /// OOM kills that succeeded.
    pub kills_ok: u64,
    /// OOM kills that failed (process already gone, etc.).
    pub kills_failed: u64,
    /// Times an OOM propagated to the parent cgroup.
    pub parent_propagations: u64,
}

// -------------------------------------------------------------------
// OomCgroupKiller
// -------------------------------------------------------------------

/// The cgroup-aware OOM killer dispatcher.
pub struct OomCgroupKiller {
    /// Registry of tracked cgroups.
    cgroups: [OomCgroupEntry; MAX_CGROUPS],
    /// Total system memory in bytes (for score computation).
    total_mem_bytes: u64,
    /// Monotonic sequence counter for events.
    seq: u64,
    /// Aggregate statistics.
    stats: OomCgroupStats,
}

impl OomCgroupKiller {
    /// Create a new killer with `total_mem_bytes` physical memory.
    pub fn new(total_mem_bytes: u64) -> Self {
        OomCgroupKiller {
            cgroups: core::array::from_fn(|_| OomCgroupEntry::empty()),
            total_mem_bytes,
            seq: 0,
            stats: OomCgroupStats::default(),
        }
    }

    /// Register a new cgroup.
    pub fn register_cgroup(
        &mut self,
        id: CgroupId,
        parent_id: CgroupId,
        policy: CgroupOomPolicy,
    ) -> Result<()> {
        if self.find_cgroup(id).is_some() {
            return Err(Error::AlreadyExists);
        }
        for i in 0..MAX_CGROUPS {
            if !self.cgroups[i].occupied {
                let depth = if parent_id.is_root() {
                    1
                } else {
                    self.find_cgroup(parent_id)
                        .map(|idx| self.cgroups[idx].depth + 1)
                        .unwrap_or(1)
                };
                if depth as usize > MAX_CGROUP_DEPTH {
                    return Err(Error::InvalidArgument);
                }
                self.cgroups[i].id = id;
                self.cgroups[i].parent_id = parent_id;
                self.cgroups[i].depth = depth;
                self.cgroups[i].policy = policy;
                self.cgroups[i].process_count = 0;
                self.cgroups[i].event_count = 0;
                self.cgroups[i].total_oom_kills = 0;
                self.cgroups[i].occupied = true;
                self.stats.cgroup_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregister a cgroup.
    pub fn unregister_cgroup(&mut self, id: CgroupId) -> Result<()> {
        let idx = self.find_cgroup(id).ok_or(Error::NotFound)?;
        self.cgroups[idx].occupied = false;
        self.stats.cgroup_count = self.stats.cgroup_count.saturating_sub(1);
        Ok(())
    }

    /// Update the memory usage snapshot for a cgroup.
    pub fn update_mem_info(&mut self, id: CgroupId, info: CgroupMemInfo) -> Result<()> {
        let idx = self.find_cgroup(id).ok_or(Error::NotFound)?;
        self.cgroups[idx].mem_info = info;
        Ok(())
    }

    /// Register a process under a cgroup.
    pub fn add_process(&mut self, cgroup_id: CgroupId, entry: ProcessEntry) -> Result<()> {
        let idx = self.find_cgroup(cgroup_id).ok_or(Error::NotFound)?;
        self.cgroups[idx].add_process(entry)
    }

    /// Remove a process from its cgroup.
    pub fn remove_process(&mut self, cgroup_id: CgroupId, pid: u32) -> bool {
        if let Some(idx) = self.find_cgroup(cgroup_id) {
            return self.cgroups[idx].remove_process(pid);
        }
        false
    }

    /// Trigger an OOM kill attempt within `cgroup_id`.
    pub fn oom_kill(&mut self, cgroup_id: CgroupId) -> Result<u32> {
        self.oom_kill_inner(cgroup_id, 0)
    }

    /// Return aggregate statistics.
    pub fn stats(&self) -> OomCgroupStats {
        self.stats
    }

    // -- Private helpers

    fn oom_kill_inner(&mut self, cgroup_id: CgroupId, depth: usize) -> Result<u32> {
        if depth > MAX_CGROUP_DEPTH {
            return Err(Error::NotFound);
        }
        let idx = self.find_cgroup(cgroup_id).ok_or(Error::NotFound)?;
        let total_mem = self.total_mem_bytes;
        let parent_id = self.cgroups[idx].parent_id;
        let victim = self.cgroups[idx].select_victim(total_mem);

        if let Some(proc) = victim {
            let pid = proc.pid;
            let score = proc.effective_score(total_mem);
            let freed = proc.rss_bytes;
            let seq = self.seq;
            self.seq += 1;
            let event = CgroupOomEvent {
                cgroup_id,
                victim_pid: pid,
                victim_score: score,
                freed_bytes: freed,
                kill_ok: true,
                seq,
            };
            self.cgroups[idx].record_event(event);
            self.cgroups[idx].remove_process(pid);
            self.stats.total_oom_events += 1;
            self.stats.kills_ok += 1;
            Ok(pid)
        } else {
            if parent_id == cgroup_id {
                self.stats.kills_failed += 1;
                return Err(Error::NotFound);
            }
            self.stats.parent_propagations += 1;
            self.oom_kill_inner(parent_id, depth + 1)
        }
    }

    fn find_cgroup(&self, id: CgroupId) -> Option<usize> {
        for i in 0..MAX_CGROUPS {
            if self.cgroups[i].occupied && self.cgroups[i].id == id {
                return Some(i);
            }
        }
        None
    }
}
