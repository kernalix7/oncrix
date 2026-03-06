// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PID namespace hierarchy for process isolation.
//!
//! PID namespaces give each container its own PID number space so that
//! independent containers can each have a PID 1 (init) process.
//! Namespaces form a strict tree: a process is visible in its own
//! namespace and every ancestor namespace, each with a distinct PID.
//!
//! # Architecture
//!
//! ```text
//! PidNsManager
//!  +-- namespaces: [PidNamespace; MAX_NAMESPACES]
//!  |    +-- PidNamespace
//!  |    |    +-- id, parent_id, level (depth)
//!  |    |    +-- mappings: [PidMapping; MAX_PIDS_PER_NS]
//!  |    |    +-- next_pid (monotonic allocator)
//!  |    |    +-- state (Active / Dying / Dead)
//!  |    +-- ...
//!  +-- PidNsStats (global counters)
//! ```
//!
//! # PID Translation
//!
//! Each mapping stores `(local_pid, global_pid)`.  The "global PID" is
//! the PID in the root (level-0) namespace.  Translation from a child
//! namespace to an ancestor walks the parent chain.
//!
//! Reference: Linux `kernel/pid_namespace.c`,
//! `include/linux/pid_namespace.h`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum namespaces in the system.
const MAX_NAMESPACES: usize = 64;

/// Maximum PID mappings per namespace.
const MAX_PIDS_PER_NS: usize = 128;

/// Maximum nesting depth.
const MAX_NS_DEPTH: u32 = 32;

/// Name buffer length.
const MAX_NAME_LEN: usize = 64;

/// PID 1 in every namespace.
const NS_INIT_PID: u64 = 1;

/// Root namespace identifier.
const ROOT_NS_ID: u64 = 0;

// ── NsState ────────────────────────────────────────────────────────

/// Lifecycle state of a PID namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NsState {
    /// Slot is unused.
    Free,
    /// Namespace is active and accepting new PIDs.
    Active,
    /// Namespace is being torn down (no new processes).
    Dying,
    /// Namespace has been fully reaped.
    Dead,
}

// ── PidMapping ─────────────────────────────────────────────────────

/// Maps a local (in-namespace) PID to the global (root-ns) PID.
#[derive(Clone, Copy)]
pub struct PidMapping {
    /// PID within this namespace.
    local_pid: u64,
    /// PID in the root namespace.
    global_pid: u64,
    /// Whether this mapping slot is occupied.
    occupied: bool,
}

impl PidMapping {
    /// Creates an empty mapping.
    pub const fn new() -> Self {
        Self {
            local_pid: 0,
            global_pid: 0,
            occupied: false,
        }
    }
}

// ── PidNamespace ───────────────────────────────────────────────────

/// A single PID namespace.
pub struct PidNamespace {
    /// Unique namespace identifier.
    ns_id: u64,
    /// Parent namespace identifier (`ROOT_NS_ID` for root).
    parent_id: u64,
    /// Nesting level (root = 0).
    level: u32,
    /// Human-readable name.
    name: [u8; MAX_NAME_LEN],
    /// Length of the name.
    name_len: usize,
    /// Lifecycle state.
    state: NsState,
    /// PID mappings.
    mappings: [PidMapping; MAX_PIDS_PER_NS],
    /// Number of active mappings.
    nr_mappings: usize,
    /// Next PID to allocate.
    next_pid: u64,
    /// Number of direct child namespaces.
    nr_children: u32,
    /// Creation timestamp (ticks).
    created_at: u64,
}

impl PidNamespace {
    /// Creates an empty (free) namespace slot.
    pub const fn new() -> Self {
        Self {
            ns_id: 0,
            parent_id: 0,
            level: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            state: NsState::Free,
            mappings: [const { PidMapping::new() }; MAX_PIDS_PER_NS],
            nr_mappings: 0,
            next_pid: NS_INIT_PID,
            nr_children: 0,
            created_at: 0,
        }
    }

    /// Allocates the next local PID and inserts a mapping.
    pub fn alloc_pid(&mut self, global_pid: u64) -> Result<u64> {
        if self.state != NsState::Active {
            return Err(Error::PermissionDenied);
        }
        let slot = self
            .mappings
            .iter()
            .position(|m| !m.occupied)
            .ok_or(Error::OutOfMemory)?;

        let local = self.next_pid;
        self.next_pid += 1;

        self.mappings[slot] = PidMapping {
            local_pid: local,
            global_pid,
            occupied: true,
        };
        self.nr_mappings += 1;
        Ok(local)
    }

    /// Removes a PID mapping by local PID.
    pub fn free_pid(&mut self, local_pid: u64) -> Result<()> {
        let idx = self
            .mappings
            .iter()
            .position(|m| m.occupied && m.local_pid == local_pid)
            .ok_or(Error::NotFound)?;

        self.mappings[idx] = PidMapping::new();
        self.nr_mappings = self.nr_mappings.saturating_sub(1);
        Ok(())
    }

    /// Translates a local PID to the global PID.
    pub fn local_to_global(&self, local_pid: u64) -> Result<u64> {
        self.mappings
            .iter()
            .find(|m| m.occupied && m.local_pid == local_pid)
            .map(|m| m.global_pid)
            .ok_or(Error::NotFound)
    }

    /// Translates a global PID to the local PID.
    pub fn global_to_local(&self, global_pid: u64) -> Result<u64> {
        self.mappings
            .iter()
            .find(|m| m.occupied && m.global_pid == global_pid)
            .map(|m| m.local_pid)
            .ok_or(Error::NotFound)
    }

    /// Returns the namespace identifier.
    pub const fn id(&self) -> u64 {
        self.ns_id
    }

    /// Returns the parent identifier.
    pub const fn parent_id(&self) -> u64 {
        self.parent_id
    }

    /// Returns the nesting level.
    pub const fn level(&self) -> u32 {
        self.level
    }

    /// Returns the current state.
    pub const fn state(&self) -> NsState {
        self.state
    }

    /// Returns the number of active mappings.
    pub const fn nr_mappings(&self) -> usize {
        self.nr_mappings
    }

    /// Returns the number of child namespaces.
    pub const fn nr_children(&self) -> u32 {
        self.nr_children
    }
}

// ── PidNsStats ─────────────────────────────────────────────────────

/// Global PID namespace statistics.
#[derive(Clone, Copy)]
pub struct PidNsStats {
    /// Total namespaces created.
    pub created: u64,
    /// Total namespaces destroyed.
    pub destroyed: u64,
    /// Total PIDs allocated.
    pub pids_allocated: u64,
    /// Total PIDs freed.
    pub pids_freed: u64,
    /// Translation requests.
    pub translations: u64,
}

impl PidNsStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            created: 0,
            destroyed: 0,
            pids_allocated: 0,
            pids_freed: 0,
            translations: 0,
        }
    }

    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

// ── PidNsManager ───────────────────────────────────────────────────

/// System-wide PID namespace manager.
pub struct PidNsManager {
    /// Namespace table.
    namespaces: [PidNamespace; MAX_NAMESPACES],
    /// Number of allocated (non-Free) namespaces.
    nr_active: usize,
    /// Next namespace identifier to assign.
    next_ns_id: u64,
    /// Aggregate statistics.
    stats: PidNsStats,
}

impl PidNsManager {
    /// Creates a new manager with the root namespace pre-created.
    pub fn new(now: u64) -> Self {
        let mut mgr = Self {
            namespaces: [const { PidNamespace::new() }; MAX_NAMESPACES],
            nr_active: 0,
            next_ns_id: 1,
            stats: PidNsStats::new(),
        };
        // Initialize root namespace in slot 0.
        let root = &mut mgr.namespaces[0];
        root.ns_id = ROOT_NS_ID;
        root.parent_id = ROOT_NS_ID;
        root.level = 0;
        root.state = NsState::Active;
        root.created_at = now;
        let name = b"root";
        let len = name.len().min(MAX_NAME_LEN);
        root.name[..len].copy_from_slice(&name[..len]);
        root.name_len = len;
        mgr.nr_active = 1;
        mgr.stats.created = 1;
        // next_ns_id already 1 — root used id 0 directly.
        mgr
    }

    /// Creates a child namespace under the given parent.
    pub fn create(&mut self, parent_id: u64, name: &[u8], now: u64) -> Result<u64> {
        // Find parent and validate.
        let parent_idx = self.find_ns(parent_id)?;
        let parent_level = self.namespaces[parent_idx].level;
        if parent_level + 1 > MAX_NS_DEPTH {
            return Err(Error::InvalidArgument);
        }

        // Find a free slot.
        let slot = self
            .namespaces
            .iter()
            .position(|ns| ns.state == NsState::Free)
            .ok_or(Error::OutOfMemory)?;

        let ns_id = self.next_ns_id;
        self.next_ns_id += 1;

        let ns = &mut self.namespaces[slot];
        ns.ns_id = ns_id;
        ns.parent_id = parent_id;
        ns.level = parent_level + 1;
        ns.state = NsState::Active;
        ns.created_at = now;
        ns.nr_mappings = 0;
        ns.next_pid = NS_INIT_PID;
        ns.nr_children = 0;

        let len = name.len().min(MAX_NAME_LEN);
        ns.name[..len].copy_from_slice(&name[..len]);
        ns.name_len = len;

        // Increment parent's child count.
        self.namespaces[parent_idx].nr_children += 1;
        self.nr_active += 1;
        self.stats.created += 1;

        Ok(ns_id)
    }

    /// Starts teardown of a namespace (transition to Dying).
    pub fn begin_destroy(&mut self, ns_id: u64) -> Result<()> {
        if ns_id == ROOT_NS_ID {
            return Err(Error::PermissionDenied);
        }
        let idx = self.find_ns(ns_id)?;
        let ns = &self.namespaces[idx];
        if ns.state != NsState::Active {
            return Err(Error::InvalidArgument);
        }
        if ns.nr_children > 0 {
            return Err(Error::Busy);
        }
        self.namespaces[idx].state = NsState::Dying;
        Ok(())
    }

    /// Completes destruction after all processes have exited.
    pub fn finish_destroy(&mut self, ns_id: u64) -> Result<()> {
        let idx = self.find_ns(ns_id)?;
        let ns = &self.namespaces[idx];
        if ns.state != NsState::Dying {
            return Err(Error::InvalidArgument);
        }
        if ns.nr_mappings > 0 {
            return Err(Error::Busy);
        }

        let parent_id = ns.parent_id;

        // Clear the namespace slot.
        self.namespaces[idx] = PidNamespace::new();
        self.nr_active = self.nr_active.saturating_sub(1);
        self.stats.destroyed += 1;

        // Decrement parent's child count.
        if let Ok(pidx) = self.find_ns(parent_id) {
            self.namespaces[pidx].nr_children = self.namespaces[pidx].nr_children.saturating_sub(1);
        }
        Ok(())
    }

    /// Allocates a PID in the given namespace.
    pub fn alloc_pid(&mut self, ns_id: u64, global_pid: u64) -> Result<u64> {
        let idx = self.find_ns(ns_id)?;
        let local = self.namespaces[idx].alloc_pid(global_pid)?;
        self.stats.pids_allocated += 1;
        Ok(local)
    }

    /// Frees a PID in the given namespace.
    pub fn free_pid(&mut self, ns_id: u64, local_pid: u64) -> Result<()> {
        let idx = self.find_ns(ns_id)?;
        self.namespaces[idx].free_pid(local_pid)?;
        self.stats.pids_freed += 1;
        Ok(())
    }

    /// Translates a local PID to the global PID.
    pub fn translate_to_global(&mut self, ns_id: u64, local_pid: u64) -> Result<u64> {
        let idx = self.find_ns(ns_id)?;
        self.stats.translations += 1;
        self.namespaces[idx].local_to_global(local_pid)
    }

    /// Translates a global PID to the local PID in a namespace.
    pub fn translate_to_local(&mut self, ns_id: u64, global_pid: u64) -> Result<u64> {
        let idx = self.find_ns(ns_id)?;
        self.stats.translations += 1;
        self.namespaces[idx].global_to_local(global_pid)
    }

    /// Returns the depth (level) of a namespace.
    pub fn ns_level(&self, ns_id: u64) -> Result<u32> {
        let idx = self.find_ns(ns_id)?;
        Ok(self.namespaces[idx].level)
    }

    /// Checks whether `ancestor_id` is an ancestor of `ns_id`.
    pub fn is_ancestor(&self, ns_id: u64, ancestor_id: u64) -> Result<bool> {
        let mut current_id = ns_id;
        for _ in 0..MAX_NS_DEPTH {
            if current_id == ancestor_id {
                return Ok(true);
            }
            if current_id == ROOT_NS_ID {
                return Ok(ancestor_id == ROOT_NS_ID);
            }
            let idx = self.find_ns(current_id)?;
            current_id = self.namespaces[idx].parent_id;
        }
        Ok(false)
    }

    /// Returns the number of active namespaces.
    pub const fn nr_active(&self) -> usize {
        self.nr_active
    }

    /// Returns a read-only reference to the statistics.
    pub const fn stats(&self) -> &PidNsStats {
        &self.stats
    }

    // ── internal helpers ───────────────────────────────────────────

    fn find_ns(&self, ns_id: u64) -> Result<usize> {
        self.namespaces
            .iter()
            .position(|ns| ns.state != NsState::Free && ns.ns_id == ns_id)
            .ok_or(Error::NotFound)
    }
}
