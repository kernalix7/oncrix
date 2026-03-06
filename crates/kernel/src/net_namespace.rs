// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Network namespace management.
//!
//! Each network namespace provides an isolated copy of the network
//! stack — its own interfaces, routing tables, firewall rules, and
//! sockets. Used by containers for network isolation.
//!
//! # Architecture
//!
//! ```text
//! NetNsManager
//!  ├── namespaces[MAX_NAMESPACES]
//!  │    ├── id, flags
//!  │    ├── interfaces, routes, sockets (counts)
//!  │    └── state: NetNsState
//!  └── stats: NetNsStats
//! ```
//!
//! # Reference
//!
//! Linux `net/core/net_namespace.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum network namespaces.
const MAX_NAMESPACES: usize = 128;

/// ID of the initial (default) network namespace.
const INIT_NET_NS_ID: u32 = 0;

// ══════════════════════════════════════════════════════════════
// NetNsState
// ══════════════════════════════════════════════════════════════

/// Lifecycle state of a network namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NetNsState {
    /// Slot is free.
    Free = 0,
    /// Namespace is being set up.
    Creating = 1,
    /// Namespace is active.
    Active = 2,
    /// Namespace is being torn down.
    Destroying = 3,
}

// ══════════════════════════════════════════════════════════════
// NetNsEntry
// ══════════════════════════════════════════════════════════════

/// A single network namespace.
#[derive(Debug, Clone, Copy)]
pub struct NetNsEntry {
    /// Namespace identifier.
    pub id: u32,
    /// Creator process ID.
    pub creator_pid: u64,
    /// Reference count.
    pub refcount: u32,
    /// Number of network interfaces.
    pub nr_interfaces: u32,
    /// Number of routing table entries.
    pub nr_routes: u32,
    /// Number of open sockets.
    pub nr_sockets: u32,
    /// Number of netfilter rules.
    pub nr_nf_rules: u32,
    /// Whether loopback is configured.
    pub has_loopback: bool,
    /// Current state.
    pub state: NetNsState,
}

impl NetNsEntry {
    /// Create a free namespace slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            creator_pid: 0,
            refcount: 0,
            nr_interfaces: 0,
            nr_routes: 0,
            nr_sockets: 0,
            nr_nf_rules: 0,
            has_loopback: false,
            state: NetNsState::Free,
        }
    }

    /// Returns `true` if the namespace is active.
    pub const fn is_active(&self) -> bool {
        matches!(self.state, NetNsState::Active)
    }
}

// ══════════════════════════════════════════════════════════════
// NetNsStats
// ══════════════════════════════════════════════════════════════

/// Network namespace subsystem statistics.
#[derive(Debug, Clone, Copy)]
pub struct NetNsStats {
    /// Total namespaces created.
    pub total_created: u64,
    /// Total namespaces destroyed.
    pub total_destroyed: u64,
    /// Total ref increments.
    pub total_refs: u64,
    /// Total ref decrements.
    pub total_unrefs: u64,
}

impl NetNsStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            total_created: 0,
            total_destroyed: 0,
            total_refs: 0,
            total_unrefs: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// NetNsManager
// ══════════════════════════════════════════════════════════════

/// Manages network namespaces.
pub struct NetNsManager {
    /// Namespace table.
    namespaces: [NetNsEntry; MAX_NAMESPACES],
    /// Next namespace ID.
    next_id: u32,
    /// Statistics.
    stats: NetNsStats,
    /// Whether the init namespace has been created.
    init_created: bool,
}

impl NetNsManager {
    /// Create a new network namespace manager.
    pub const fn new() -> Self {
        Self {
            namespaces: [const { NetNsEntry::empty() }; MAX_NAMESPACES],
            next_id: 1,
            stats: NetNsStats::new(),
            init_created: false,
        }
    }

    /// Initialise the default (init) network namespace.
    pub fn init(&mut self) -> Result<()> {
        if self.init_created {
            return Err(Error::AlreadyExists);
        }
        self.namespaces[0] = NetNsEntry {
            id: INIT_NET_NS_ID,
            creator_pid: 1,
            refcount: 1,
            has_loopback: true,
            nr_interfaces: 1,
            state: NetNsState::Active,
            ..NetNsEntry::empty()
        };
        self.init_created = true;
        self.stats.total_created += 1;
        Ok(())
    }

    /// Create a new network namespace.
    pub fn create(&mut self, creator_pid: u64) -> Result<u32> {
        let slot = self
            .namespaces
            .iter()
            .position(|ns| matches!(ns.state, NetNsState::Free))
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_id;
        self.next_id += 1;
        self.namespaces[slot] = NetNsEntry {
            id,
            creator_pid,
            refcount: 1,
            has_loopback: true,
            nr_interfaces: 1,
            state: NetNsState::Active,
            ..NetNsEntry::empty()
        };
        self.stats.total_created += 1;
        Ok(id)
    }

    /// Increment the reference count of a namespace.
    pub fn get_ref(&mut self, id: u32) -> Result<()> {
        let slot = self.find_ns(id)?;
        self.namespaces[slot].refcount += 1;
        self.stats.total_refs += 1;
        Ok(())
    }

    /// Decrement the reference count. Destroys the namespace when
    /// the count reaches zero.
    pub fn put_ref(&mut self, id: u32) -> Result<()> {
        let slot = self.find_ns(id)?;
        self.stats.total_unrefs += 1;
        self.namespaces[slot].refcount = self.namespaces[slot].refcount.saturating_sub(1);
        if self.namespaces[slot].refcount == 0 && id != INIT_NET_NS_ID {
            self.namespaces[slot].state = NetNsState::Destroying;
            self.namespaces[slot] = NetNsEntry::empty();
            self.stats.total_destroyed += 1;
        }
        Ok(())
    }

    /// Register a network interface in a namespace.
    pub fn add_interface(&mut self, ns_id: u32) -> Result<()> {
        let slot = self.find_ns(ns_id)?;
        self.namespaces[slot].nr_interfaces += 1;
        Ok(())
    }

    /// Add a route to a namespace.
    pub fn add_route(&mut self, ns_id: u32) -> Result<()> {
        let slot = self.find_ns(ns_id)?;
        self.namespaces[slot].nr_routes += 1;
        Ok(())
    }

    /// Add a socket to a namespace.
    pub fn add_socket(&mut self, ns_id: u32) -> Result<()> {
        let slot = self.find_ns(ns_id)?;
        self.namespaces[slot].nr_sockets += 1;
        Ok(())
    }

    /// Return namespace entry.
    pub fn get(&self, id: u32) -> Result<&NetNsEntry> {
        let slot = self.find_ns(id)?;
        Ok(&self.namespaces[slot])
    }

    /// Return active namespace count.
    pub fn active_count(&self) -> usize {
        self.namespaces.iter().filter(|ns| ns.is_active()).count()
    }

    /// Return statistics.
    pub fn stats(&self) -> NetNsStats {
        self.stats
    }

    // ── Internal ─────────────────────────────────────────────

    fn find_ns(&self, id: u32) -> Result<usize> {
        self.namespaces
            .iter()
            .position(|ns| ns.is_active() && ns.id == id)
            .ok_or(Error::NotFound)
    }
}
