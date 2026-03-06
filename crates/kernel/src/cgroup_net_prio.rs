// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cgroup network priority controller.
//!
//! Assigns a per-interface network priority to traffic originating
//! from tasks in a cgroup. The priority is applied as the socket
//! `SO_PRIORITY` for outgoing packets, which can then be used by
//! traffic control (tc) queueing disciplines for scheduling.
//!
//! # Architecture
//!
//! ```text
//! NetPrioController
//!  ├── groups[MAX_GROUPS]
//!  │    ├── id, parent_id
//!  │    ├── ifprio_map[MAX_INTERFACES]  (ifindex → priority)
//!  │    └── default_prio
//!  └── stats: NetPrioStats
//! ```
//!
//! # Reference
//!
//! Linux `net/core/netprio_cgroup.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum number of net_prio cgroups.
const MAX_GROUPS: usize = 128;

/// Maximum number of network interfaces per cgroup.
const MAX_INTERFACES: usize = 32;

// ══════════════════════════════════════════════════════════════
// InterfacePriority
// ══════════════════════════════════════════════════════════════

/// Maps a network interface to a priority value.
#[derive(Debug, Clone, Copy)]
pub struct InterfacePriority {
    /// Network interface index.
    pub ifindex: u32,
    /// Priority value (0 = not set).
    pub priority: u32,
    /// Whether this mapping is active.
    pub active: bool,
}

impl InterfacePriority {
    /// Create an inactive mapping.
    const fn empty() -> Self {
        Self {
            ifindex: 0,
            priority: 0,
            active: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// NetPrioGroup
// ══════════════════════════════════════════════════════════════

/// A single net_prio cgroup entry.
#[derive(Clone, Copy)]
pub struct NetPrioGroup {
    /// Cgroup identifier.
    pub id: u32,
    /// Parent cgroup ID (0 = root).
    pub parent_id: u32,
    /// Per-interface priority mappings.
    pub ifprio_map: [InterfacePriority; MAX_INTERFACES],
    /// Default priority for interfaces without explicit mapping.
    pub default_prio: u32,
    /// Whether this entry is active.
    pub active: bool,
}

impl NetPrioGroup {
    /// Create an inactive group.
    const fn empty() -> Self {
        Self {
            id: 0,
            parent_id: 0,
            ifprio_map: [const { InterfacePriority::empty() }; MAX_INTERFACES],
            default_prio: 0,
            active: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// NetPrioStats
// ══════════════════════════════════════════════════════════════

/// Statistics for the net_prio controller.
#[derive(Debug, Clone, Copy)]
pub struct NetPrioStats {
    /// Total groups created.
    pub groups_created: u64,
    /// Total groups removed.
    pub groups_removed: u64,
    /// Total priority mappings set.
    pub mappings_set: u64,
    /// Total priority lookups performed.
    pub lookups: u64,
}

impl NetPrioStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            groups_created: 0,
            groups_removed: 0,
            mappings_set: 0,
            lookups: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// NetPrioController
// ══════════════════════════════════════════════════════════════

/// Cgroup net_prio controller.
pub struct NetPrioController {
    /// Cgroup entries.
    groups: [NetPrioGroup; MAX_GROUPS],
    /// Next cgroup ID.
    next_id: u32,
    /// Statistics.
    stats: NetPrioStats,
}

impl NetPrioController {
    /// Create a new net_prio controller.
    pub const fn new() -> Self {
        Self {
            groups: [const { NetPrioGroup::empty() }; MAX_GROUPS],
            next_id: 1,
            stats: NetPrioStats::new(),
        }
    }

    /// Create a new net_prio cgroup.
    pub fn create_group(&mut self, parent_id: u32) -> Result<u32> {
        let slot = self
            .groups
            .iter()
            .position(|g| !g.active)
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_id;
        self.next_id += 1;
        self.groups[slot] = NetPrioGroup {
            id,
            parent_id,
            active: true,
            ..NetPrioGroup::empty()
        };
        self.stats.groups_created += 1;
        Ok(id)
    }

    /// Remove a net_prio cgroup.
    pub fn remove_group(&mut self, id: u32) -> Result<()> {
        let slot = self.find_group(id)?;
        self.groups[slot] = NetPrioGroup::empty();
        self.stats.groups_removed += 1;
        Ok(())
    }

    /// Set the priority for a specific interface in a cgroup.
    pub fn set_priority(&mut self, group_id: u32, ifindex: u32, priority: u32) -> Result<()> {
        let slot = self.find_group(group_id)?;
        // Find existing mapping or a free slot.
        let map_slot = self.groups[slot]
            .ifprio_map
            .iter()
            .position(|m| m.active && m.ifindex == ifindex)
            .or_else(|| self.groups[slot].ifprio_map.iter().position(|m| !m.active))
            .ok_or(Error::OutOfMemory)?;
        self.groups[slot].ifprio_map[map_slot] = InterfacePriority {
            ifindex,
            priority,
            active: true,
        };
        self.stats.mappings_set += 1;
        Ok(())
    }

    /// Look up the priority for a given interface in a cgroup.
    /// Falls back to the default priority if no explicit mapping.
    pub fn lookup_priority(&mut self, group_id: u32, ifindex: u32) -> Result<u32> {
        let slot = self.find_group(group_id)?;
        self.stats.lookups += 1;
        let prio = self.groups[slot]
            .ifprio_map
            .iter()
            .find(|m| m.active && m.ifindex == ifindex)
            .map(|m| m.priority)
            .unwrap_or(self.groups[slot].default_prio);
        Ok(prio)
    }

    /// Set the default priority for a cgroup.
    pub fn set_default_priority(&mut self, group_id: u32, priority: u32) -> Result<()> {
        let slot = self.find_group(group_id)?;
        self.groups[slot].default_prio = priority;
        Ok(())
    }

    /// Return the number of active cgroups.
    pub fn active_count(&self) -> usize {
        self.groups.iter().filter(|g| g.active).count()
    }

    /// Return statistics.
    pub fn stats(&self) -> NetPrioStats {
        self.stats
    }

    // ── Internal ─────────────────────────────────────────────

    fn find_group(&self, id: u32) -> Result<usize> {
        self.groups
            .iter()
            .position(|g| g.active && g.id == id)
            .ok_or(Error::NotFound)
    }
}
