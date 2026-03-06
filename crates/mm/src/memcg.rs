// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory cgroup controller for per-group memory accounting
//! and limits.
//!
//! Implements Linux-style memory cgroups with:
//! - Per-group memory usage tracking and hard/soft limits
//! - Swap and kernel memory accounting
//! - OOM (out-of-memory) control per cgroup
//! - Event counters (page in/out, faults)
//! - PID attachment for process-to-cgroup mapping
//!
//! # Types
//!
//! - [`MemcgGroup`] — a single memory cgroup with counters
//! - [`MemcgRegistry`] — registry of all memory cgroups
//! - [`MemcgEventType`] — event types for page accounting

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of memory cgroup groups.
const MAX_MEMCG_GROUPS: usize = 64;

/// Standard page size in bytes (4 KiB).
const _PAGE_SIZE: u64 = 4096;

/// Sentinel value meaning "no memory limit".
const MEMCG_NO_LIMIT: u64 = u64::MAX;

/// Maximum length of a cgroup name in bytes.
const MAX_MEMCG_NAME: usize = 32;

/// Minimum OOM kill score adjustment.
const _OOM_KILL_SCORE_ADJ_MIN: i32 = -1000;

/// Maximum OOM kill score adjustment.
const _OOM_KILL_SCORE_ADJ_MAX: i32 = 1000;

/// Maximum number of PIDs attachable to a single cgroup.
const MAX_ATTACHED_PIDS: usize = 32;

// -------------------------------------------------------------------
// MemcgState
// -------------------------------------------------------------------

/// State of a memory cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MemcgState {
    /// Cgroup is active and accounting memory.
    #[default]
    Active,
    /// Cgroup is frozen (no new charges allowed).
    Frozen,
    /// Cgroup has been taken offline.
    Offline,
}

// -------------------------------------------------------------------
// MemcgCounters
// -------------------------------------------------------------------

/// Memory usage counters for a cgroup.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemcgCounters {
    /// Current memory usage in bytes.
    pub usage: u64,
    /// Hard memory limit in bytes.
    pub limit: u64,
    /// Peak memory usage in bytes.
    pub max_usage: u64,
    /// Number of times allocation failed due to limit.
    pub failcnt: u64,
    /// Current swap usage in bytes.
    pub swap_usage: u64,
    /// Swap limit in bytes.
    pub swap_limit: u64,
    /// Kernel memory usage in bytes.
    pub kmem_usage: u64,
    /// Kernel memory limit in bytes.
    pub kmem_limit: u64,
    /// Page cache usage in bytes.
    pub cache_usage: u64,
}

// -------------------------------------------------------------------
// MemcgOomControl
// -------------------------------------------------------------------

/// OOM (out-of-memory) control settings for a cgroup.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemcgOomControl {
    /// Whether OOM killing is disabled for this cgroup.
    pub oom_kill_disable: bool,
    /// Whether this cgroup is currently under OOM pressure.
    pub under_oom: bool,
    /// Number of OOM kills triggered in this cgroup.
    pub oom_kill_count: u64,
}

// -------------------------------------------------------------------
// MemcgEventCounters
// -------------------------------------------------------------------

/// Event counters tracking page activity in a cgroup.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemcgEventCounters {
    /// Pages paged in.
    pub pgpgin: u64,
    /// Pages paged out.
    pub pgpgout: u64,
    /// Page faults.
    pub pgfault: u64,
    /// Major page faults.
    pub pgmajfault: u64,
    /// Inactive anonymous memory in bytes.
    pub inactive_anon: u64,
    /// Active anonymous memory in bytes.
    pub active_anon: u64,
    /// Inactive file-backed memory in bytes.
    pub inactive_file: u64,
    /// Active file-backed memory in bytes.
    pub active_file: u64,
}

// -------------------------------------------------------------------
// MemcgEventType
// -------------------------------------------------------------------

/// Types of memory cgroup events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MemcgEventType {
    /// A page was read in from storage.
    #[default]
    PageIn,
    /// A page was written out to storage.
    PageOut,
    /// A page fault occurred.
    PageFault,
    /// A major page fault occurred (required I/O).
    PageMajFault,
}

// -------------------------------------------------------------------
// MemcgGroup
// -------------------------------------------------------------------

/// A single memory cgroup with usage counters, limits, and
/// OOM control.
#[derive(Debug, Clone, Copy)]
pub struct MemcgGroup {
    /// Unique identifier for this cgroup.
    pub id: u32,
    /// Name of this cgroup (UTF-8 bytes).
    pub name: [u8; MAX_MEMCG_NAME],
    /// Length of the name in bytes.
    pub name_len: usize,
    /// Parent cgroup identifier, if any.
    pub parent_id: Option<u32>,
    /// Memory usage counters.
    pub counters: MemcgCounters,
    /// OOM control settings.
    pub oom: MemcgOomControl,
    /// Event counters.
    pub events: MemcgEventCounters,
    /// Current state.
    pub state: MemcgState,
    /// Soft memory limit in bytes.
    pub soft_limit: u64,
    /// Low watermark for memory reclaim.
    pub watermark_low: u64,
    /// High watermark for memory reclaim.
    pub watermark_high: u64,
    /// Whether this slot is in use.
    pub active: bool,
    /// PIDs attached to this cgroup.
    pub attached_pids: [u64; MAX_ATTACHED_PIDS],
    /// Number of attached PIDs.
    pub pid_count: usize,
}

impl MemcgGroup {
    /// Creates a new empty (inactive) cgroup slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_MEMCG_NAME],
            name_len: 0,
            parent_id: None,
            counters: MemcgCounters {
                usage: 0,
                limit: MEMCG_NO_LIMIT,
                max_usage: 0,
                failcnt: 0,
                swap_usage: 0,
                swap_limit: MEMCG_NO_LIMIT,
                kmem_usage: 0,
                kmem_limit: MEMCG_NO_LIMIT,
                cache_usage: 0,
            },
            oom: MemcgOomControl {
                oom_kill_disable: false,
                under_oom: false,
                oom_kill_count: 0,
            },
            events: MemcgEventCounters {
                pgpgin: 0,
                pgpgout: 0,
                pgfault: 0,
                pgmajfault: 0,
                inactive_anon: 0,
                active_anon: 0,
                inactive_file: 0,
                active_file: 0,
            },
            state: MemcgState::Active,
            soft_limit: MEMCG_NO_LIMIT,
            watermark_low: 0,
            watermark_high: 0,
            active: false,
            attached_pids: [0u64; MAX_ATTACHED_PIDS],
            pid_count: 0,
        }
    }
}

// -------------------------------------------------------------------
// MemcgRegistry
// -------------------------------------------------------------------

/// Registry managing all memory cgroups in the system.
pub struct MemcgRegistry {
    /// Array of cgroup slots.
    groups: [MemcgGroup; MAX_MEMCG_GROUPS],
    /// Next cgroup identifier to assign.
    next_id: u32,
    /// Number of active cgroups.
    count: usize,
}

impl Default for MemcgRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MemcgRegistry {
    /// Creates a new, empty cgroup registry.
    pub const fn new() -> Self {
        const EMPTY: MemcgGroup = MemcgGroup::empty();
        Self {
            groups: [EMPTY; MAX_MEMCG_GROUPS],
            next_id: 1,
            count: 0,
        }
    }

    /// Returns the number of active cgroups.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no cgroups are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Creates a new memory cgroup with the given name and
    /// optional parent.
    ///
    /// Returns the new cgroup's identifier on success.
    pub fn create(&mut self, name: &[u8], parent: Option<u32>) -> Result<u32> {
        if name.is_empty() || name.len() > MAX_MEMCG_NAME {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_MEMCG_GROUPS {
            return Err(Error::OutOfMemory);
        }
        if let Some(pid) = parent {
            if !self.find_active(pid) {
                return Err(Error::NotFound);
            }
        }

        let slot = self.find_free_slot().ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let group = &mut self.groups[slot];
        *group = MemcgGroup::empty();
        group.id = id;
        group.active = true;
        group.parent_id = parent;
        group.name_len = name.len();

        let dest = &mut group.name[..name.len()];
        dest.copy_from_slice(name);

        self.count += 1;
        Ok(id)
    }

    /// Destroys a memory cgroup by identifier.
    ///
    /// Fails if the cgroup has attached PIDs.
    pub fn destroy(&mut self, id: u32) -> Result<()> {
        let idx = self.index_of(id)?;
        if self.groups[idx].pid_count > 0 {
            return Err(Error::Busy);
        }
        self.groups[idx].active = false;
        self.groups[idx].state = MemcgState::Offline;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Sets the hard memory limit for a cgroup.
    pub fn set_limit(&mut self, id: u32, limit: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        self.groups[idx].counters.limit = limit;
        Ok(())
    }

    /// Sets the soft memory limit for a cgroup.
    pub fn set_soft_limit(&mut self, id: u32, limit: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        self.groups[idx].soft_limit = limit;
        Ok(())
    }

    /// Sets the swap limit for a cgroup.
    pub fn set_swap_limit(&mut self, id: u32, limit: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        self.groups[idx].counters.swap_limit = limit;
        Ok(())
    }

    /// Charges `pages` pages of memory to a cgroup.
    ///
    /// Increments usage by `pages * PAGE_SIZE`. If the new usage
    /// exceeds the hard limit, sets the OOM flag and returns
    /// [`Error::OutOfMemory`].
    pub fn charge(&mut self, id: u32, pages: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        let group = &mut self.groups[idx];

        if group.state == MemcgState::Frozen {
            return Err(Error::Busy);
        }

        let bytes = pages.saturating_mul(_PAGE_SIZE);
        let new_usage = group.counters.usage.saturating_add(bytes);

        if group.counters.limit != MEMCG_NO_LIMIT && new_usage > group.counters.limit {
            group.counters.failcnt = group.counters.failcnt.saturating_add(1);
            group.oom.under_oom = true;
            if !group.oom.oom_kill_disable {
                group.oom.oom_kill_count = group.oom.oom_kill_count.saturating_add(1);
            }
            return Err(Error::OutOfMemory);
        }

        group.counters.usage = new_usage;
        if new_usage > group.counters.max_usage {
            group.counters.max_usage = new_usage;
        }
        Ok(())
    }

    /// Uncharges `pages` pages of memory from a cgroup.
    pub fn uncharge(&mut self, id: u32, pages: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        let bytes = pages.saturating_mul(_PAGE_SIZE);
        let group = &mut self.groups[idx];
        group.counters.usage = group.counters.usage.saturating_sub(bytes);

        if group.counters.limit == MEMCG_NO_LIMIT || group.counters.usage <= group.counters.limit {
            group.oom.under_oom = false;
        }
        Ok(())
    }

    /// Charges kernel memory bytes to a cgroup.
    pub fn charge_kmem(&mut self, id: u32, bytes: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        let group = &mut self.groups[idx];
        let new_usage = group.counters.kmem_usage.saturating_add(bytes);

        if group.counters.kmem_limit != MEMCG_NO_LIMIT && new_usage > group.counters.kmem_limit {
            group.counters.failcnt = group.counters.failcnt.saturating_add(1);
            return Err(Error::OutOfMemory);
        }

        group.counters.kmem_usage = new_usage;
        Ok(())
    }

    /// Uncharges kernel memory bytes from a cgroup.
    pub fn uncharge_kmem(&mut self, id: u32, bytes: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        self.groups[idx].counters.kmem_usage =
            self.groups[idx].counters.kmem_usage.saturating_sub(bytes);
        Ok(())
    }

    /// Attaches a PID to a cgroup.
    pub fn attach_pid(&mut self, id: u32, pid: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        let group = &mut self.groups[idx];

        // Check for duplicate.
        for i in 0..group.pid_count {
            if group.attached_pids[i] == pid {
                return Err(Error::AlreadyExists);
            }
        }

        if group.pid_count >= MAX_ATTACHED_PIDS {
            return Err(Error::OutOfMemory);
        }

        group.attached_pids[group.pid_count] = pid;
        group.pid_count += 1;
        Ok(())
    }

    /// Detaches a PID from a cgroup.
    pub fn detach_pid(&mut self, id: u32, pid: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        let group = &mut self.groups[idx];

        let pos = (0..group.pid_count)
            .find(|&i| group.attached_pids[i] == pid)
            .ok_or(Error::NotFound)?;

        // Swap-remove.
        group.pid_count -= 1;
        if pos < group.pid_count {
            group.attached_pids[pos] = group.attached_pids[group.pid_count];
        }
        group.attached_pids[group.pid_count] = 0;
        Ok(())
    }

    /// Returns the current memory usage of a cgroup in bytes.
    pub fn get_usage(&self, id: u32) -> Result<u64> {
        let idx = self.index_of_ref(id)?;
        Ok(self.groups[idx].counters.usage)
    }

    /// Returns a copy of the memory counters for a cgroup.
    pub fn get_stats(&self, id: u32) -> Result<MemcgCounters> {
        let idx = self.index_of_ref(id)?;
        Ok(self.groups[idx].counters)
    }

    /// Returns whether a cgroup is currently under OOM
    /// pressure.
    pub fn is_under_oom(&self, id: u32) -> Result<bool> {
        let idx = self.index_of_ref(id)?;
        Ok(self.groups[idx].oom.under_oom)
    }

    /// Enables or disables OOM killing for a cgroup.
    pub fn set_oom_kill_disable(&mut self, id: u32, disable: bool) -> Result<()> {
        let idx = self.index_of(id)?;
        self.groups[idx].oom.oom_kill_disable = disable;
        Ok(())
    }

    /// Records a memory event for a cgroup.
    pub fn record_event(&mut self, id: u32, event: MemcgEventType) {
        if let Ok(idx) = self.index_of(id) {
            let ev = &mut self.groups[idx].events;
            match event {
                MemcgEventType::PageIn => {
                    ev.pgpgin = ev.pgpgin.saturating_add(1);
                }
                MemcgEventType::PageOut => {
                    ev.pgpgout = ev.pgpgout.saturating_add(1);
                }
                MemcgEventType::PageFault => {
                    ev.pgfault = ev.pgfault.saturating_add(1);
                }
                MemcgEventType::PageMajFault => {
                    ev.pgmajfault = ev.pgmajfault.saturating_add(1);
                }
            }
        }
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    /// Finds a free slot index in the groups array.
    fn find_free_slot(&self) -> Option<usize> {
        self.groups.iter().position(|g| !g.active)
    }

    /// Returns `true` if a cgroup with the given id is active.
    fn find_active(&self, id: u32) -> bool {
        self.groups.iter().any(|g| g.active && g.id == id)
    }

    /// Returns the index of an active cgroup (mutable path).
    fn index_of(&mut self, id: u32) -> Result<usize> {
        self.groups
            .iter()
            .position(|g| g.active && g.id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns the index of an active cgroup (shared path).
    fn index_of_ref(&self, id: u32) -> Result<usize> {
        self.groups
            .iter()
            .position(|g| g.active && g.id == id)
            .ok_or(Error::NotFound)
    }
}
