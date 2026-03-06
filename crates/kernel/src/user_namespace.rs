// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! User namespace management.
//!
//! Provides UID/GID isolation via ID mapping tables. Capabilities
//! are scoped to the owning namespace. Supports hierarchical
//! nesting, `ns_capable` checks, and overflow ID mapping.
//!
//! Reference: Linux `kernel/user_namespace.c`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────

/// Maximum user namespaces.
const MAX_USER_NS: usize = 64;

/// Maximum ID map entries per direction (uid or gid).
const MAX_ID_MAP_ENTRIES: usize = 5;

/// Maximum nesting depth for user namespaces.
const MAX_NS_DEPTH: u32 = 32;

/// Initial (root) user namespace ID.
const INIT_USER_NS_ID: u64 = 1;

/// Number of capability words (128 caps).
const CAP_WORDS: usize = 2;

/// Overflows-to: ID returned for unmapped IDs.
const OVERFLOW_UID: u32 = 65534;

/// Overflows-to: GID returned for unmapped GIDs.
const OVERFLOW_GID: u32 = 65534;

/// A single ID mapping range entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct IdMapEntry {
    /// Starting ID in the namespace.
    pub ns_id: u32,
    /// Starting ID in the parent (host) namespace.
    pub host_id: u32,
    /// Number of IDs in this range.
    pub count: u32,
}

impl IdMapEntry {
    /// Empty / unused entry.
    const fn empty() -> Self {
        Self {
            ns_id: 0,
            host_id: 0,
            count: 0,
        }
    }

    /// Check if a namespace ID falls within this range.
    fn contains_ns_id(&self, id: u32) -> bool {
        self.count > 0 && id >= self.ns_id && id < self.ns_id + self.count
    }

    /// Check if a host ID falls within this range.
    fn contains_host_id(&self, id: u32) -> bool {
        self.count > 0 && id >= self.host_id && id < self.host_id + self.count
    }

    /// Map a namespace ID to a host ID.
    fn ns_to_host(&self, ns_id: u32) -> u32 {
        self.host_id + (ns_id - self.ns_id)
    }

    /// Map a host ID to a namespace ID.
    fn host_to_ns(&self, host_id: u32) -> u32 {
        self.ns_id + (host_id - self.host_id)
    }
}

/// Capability bitmask for namespace-scoped checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NsCapSet {
    /// Capability bits.
    bits: [u64; CAP_WORDS],
}

impl NsCapSet {
    /// All capabilities raised.
    const fn full() -> Self {
        Self {
            bits: [u64::MAX; CAP_WORDS],
        }
    }

    /// No capabilities.
    const fn empty() -> Self {
        Self {
            bits: [0; CAP_WORDS],
        }
    }

    /// Check if capability `cap` is raised.
    fn has(&self, cap: u32) -> bool {
        let word = (cap / 64) as usize;
        let bit = cap % 64;
        if word >= CAP_WORDS {
            return false;
        }
        (self.bits[word] & (1u64 << bit)) != 0
    }
}

/// Namespace lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NsState {
    /// Slot is free.
    Free,
    /// Namespace is active.
    Active,
}

/// A user namespace.
#[derive(Debug, Clone, Copy)]
struct UserNamespace {
    /// Namespace ID.
    id: u64,
    /// Parent namespace ID (0 for init_user_ns).
    parent_id: u64,
    /// UID of the process that created this namespace.
    owner_uid: u32,
    /// Depth in the namespace hierarchy.
    depth: u32,
    /// UID mapping entries.
    uid_map: [IdMapEntry; MAX_ID_MAP_ENTRIES],
    /// Number of configured UID map entries.
    uid_map_count: u32,
    /// GID mapping entries.
    gid_map: [IdMapEntry; MAX_ID_MAP_ENTRIES],
    /// Number of configured GID map entries.
    gid_map_count: u32,
    /// Capabilities granted to the namespace owner.
    owner_caps: NsCapSet,
    /// Reference count.
    ref_count: u32,
    /// Lifecycle state.
    state: NsState,
}

/// Statistics.
#[derive(Debug, Clone, Copy)]
pub struct UserNsStats {
    /// Total namespaces created.
    pub total_created: u64,
    /// Total namespaces destroyed.
    pub total_destroyed: u64,
    /// Total UID map writes.
    pub total_uid_maps: u64,
    /// Total GID map writes.
    pub total_gid_maps: u64,
    /// Total ns_capable checks.
    pub total_cap_checks: u64,
    /// Active namespace count.
    pub active_count: u32,
}

/// Global user namespace manager.
pub struct UserNsTable {
    /// Namespace pool.
    namespaces: [UserNamespace; MAX_USER_NS],
    /// Next namespace ID.
    next_ns_id: u64,
    /// Statistics.
    stats: UserNsStats,
}

impl UserNsTable {
    /// Create a new user namespace table.
    pub const fn new() -> Self {
        let ns = UserNamespace {
            id: 0,
            parent_id: 0,
            owner_uid: 0,
            depth: 0,
            uid_map: [IdMapEntry::empty(); MAX_ID_MAP_ENTRIES],
            uid_map_count: 0,
            gid_map: [IdMapEntry::empty(); MAX_ID_MAP_ENTRIES],
            gid_map_count: 0,
            owner_caps: NsCapSet::empty(),
            ref_count: 0,
            state: NsState::Free,
        };
        Self {
            namespaces: [ns; MAX_USER_NS],
            next_ns_id: INIT_USER_NS_ID,
            stats: UserNsStats {
                total_created: 0,
                total_destroyed: 0,
                total_uid_maps: 0,
                total_gid_maps: 0,
                total_cap_checks: 0,
                active_count: 0,
            },
        }
    }

    /// Create a new user namespace.
    ///
    /// The creating process' UID becomes the namespace owner.
    /// The owner gains full capabilities within the new namespace.
    pub fn create_ns(&mut self, parent_id: u64, owner_uid: u32) -> Result<u64> {
        let depth = if parent_id == 0 {
            0
        } else {
            let pidx = self.find_ns(parent_id)?;
            let d = self.namespaces[pidx].depth + 1;
            if d >= MAX_NS_DEPTH {
                return Err(Error::InvalidArgument);
            }
            d
        };
        let pos = self
            .namespaces
            .iter()
            .position(|n| n.state == NsState::Free)
            .ok_or(Error::OutOfMemory)?;
        let ns_id = self.next_ns_id;
        self.next_ns_id += 1;
        let ns = &mut self.namespaces[pos];
        ns.id = ns_id;
        ns.parent_id = parent_id;
        ns.owner_uid = owner_uid;
        ns.depth = depth;
        ns.uid_map = [IdMapEntry::empty(); MAX_ID_MAP_ENTRIES];
        ns.uid_map_count = 0;
        ns.gid_map = [IdMapEntry::empty(); MAX_ID_MAP_ENTRIES];
        ns.gid_map_count = 0;
        ns.owner_caps = NsCapSet::full();
        ns.ref_count = 1;
        ns.state = NsState::Active;
        self.stats.total_created += 1;
        self.stats.active_count += 1;
        Ok(ns_id)
    }

    /// Write UID map entries for a user namespace.
    ///
    /// Can only be written once (before any process uses the ns).
    pub fn write_uid_map(&mut self, ns_id: u64, entries: &[IdMapEntry]) -> Result<()> {
        if entries.is_empty() || entries.len() > MAX_ID_MAP_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        let idx = self.find_ns(ns_id)?;
        if self.namespaces[idx].uid_map_count > 0 {
            return Err(Error::AlreadyExists);
        }
        self.validate_map_entries(entries)?;
        let ns = &mut self.namespaces[idx];
        for (i, entry) in entries.iter().enumerate() {
            ns.uid_map[i] = *entry;
        }
        ns.uid_map_count = entries.len() as u32;
        self.stats.total_uid_maps += 1;
        Ok(())
    }

    /// Write GID map entries for a user namespace.
    pub fn write_gid_map(&mut self, ns_id: u64, entries: &[IdMapEntry]) -> Result<()> {
        if entries.is_empty() || entries.len() > MAX_ID_MAP_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        let idx = self.find_ns(ns_id)?;
        if self.namespaces[idx].gid_map_count > 0 {
            return Err(Error::AlreadyExists);
        }
        self.validate_map_entries(entries)?;
        let ns = &mut self.namespaces[idx];
        for (i, entry) in entries.iter().enumerate() {
            ns.gid_map[i] = *entry;
        }
        ns.gid_map_count = entries.len() as u32;
        self.stats.total_gid_maps += 1;
        Ok(())
    }

    /// Map a UID from the namespace to the host.
    ///
    /// Returns `OVERFLOW_UID` if the ID is not mapped.
    pub fn map_uid_to_host(&self, ns_id: u64, ns_uid: u32) -> Result<u32> {
        let idx = self.find_ns(ns_id)?;
        let ns = &self.namespaces[idx];
        let count = ns.uid_map_count as usize;
        for entry in &ns.uid_map[..count] {
            if entry.contains_ns_id(ns_uid) {
                return Ok(entry.ns_to_host(ns_uid));
            }
        }
        Ok(OVERFLOW_UID)
    }

    /// Map a UID from the host into the namespace.
    ///
    /// Returns `OVERFLOW_UID` if the ID is not mapped.
    pub fn map_uid_from_host(&self, ns_id: u64, host_uid: u32) -> Result<u32> {
        let idx = self.find_ns(ns_id)?;
        let ns = &self.namespaces[idx];
        let count = ns.uid_map_count as usize;
        for entry in &ns.uid_map[..count] {
            if entry.contains_host_id(host_uid) {
                return Ok(entry.host_to_ns(host_uid));
            }
        }
        Ok(OVERFLOW_UID)
    }

    /// Map a GID from the namespace to the host.
    pub fn map_gid_to_host(&self, ns_id: u64, ns_gid: u32) -> Result<u32> {
        let idx = self.find_ns(ns_id)?;
        let ns = &self.namespaces[idx];
        let count = ns.gid_map_count as usize;
        for entry in &ns.gid_map[..count] {
            if entry.contains_ns_id(ns_gid) {
                return Ok(entry.ns_to_host(ns_gid));
            }
        }
        Ok(OVERFLOW_GID)
    }

    /// Map a GID from the host into the namespace.
    pub fn map_gid_from_host(&self, ns_id: u64, host_gid: u32) -> Result<u32> {
        let idx = self.find_ns(ns_id)?;
        let ns = &self.namespaces[idx];
        let count = ns.gid_map_count as usize;
        for entry in &ns.gid_map[..count] {
            if entry.contains_host_id(host_gid) {
                return Ok(entry.host_to_ns(host_gid));
            }
        }
        Ok(OVERFLOW_GID)
    }

    /// Check if a caller has a capability within a namespace.
    ///
    /// Walks up the namespace hierarchy: if the caller's
    /// user namespace is an ancestor (or is) the target, and
    /// the caller holds the capability, the check passes.
    pub fn ns_capable(&mut self, target_ns_id: u64, caller_ns_id: u64, cap: u32) -> Result<bool> {
        self.stats.total_cap_checks += 1;
        // Walk from target up to root, looking for caller's ns.
        let mut current_id = target_ns_id;
        loop {
            if current_id == caller_ns_id {
                let idx = self.find_ns(caller_ns_id)?;
                return Ok(self.namespaces[idx].owner_caps.has(cap));
            }
            let idx = self.find_ns(current_id)?;
            let parent = self.namespaces[idx].parent_id;
            if parent == 0 || current_id == parent {
                break;
            }
            current_id = parent;
        }
        Ok(false)
    }

    /// Get the owner UID of a namespace.
    pub fn get_owner(&self, ns_id: u64) -> Result<u32> {
        let idx = self.find_ns(ns_id)?;
        Ok(self.namespaces[idx].owner_uid)
    }

    /// Increment reference count.
    pub fn get_ns_ref(&mut self, ns_id: u64) -> Result<()> {
        let idx = self.find_ns(ns_id)?;
        self.namespaces[idx].ref_count += 1;
        Ok(())
    }

    /// Decrement reference count, freeing if zero.
    pub fn put_ns_ref(&mut self, ns_id: u64) -> Result<()> {
        let idx = self.find_ns(ns_id)?;
        let ns = &mut self.namespaces[idx];
        ns.ref_count = ns.ref_count.saturating_sub(1);
        if ns.ref_count == 0 {
            ns.state = NsState::Free;
            self.stats.total_destroyed += 1;
            self.stats.active_count = self.stats.active_count.saturating_sub(1);
        }
        Ok(())
    }

    /// Return statistics.
    pub fn stats(&self) -> &UserNsStats {
        &self.stats
    }

    // ── Internal helpers ────────────────────────────────────────

    /// Find a namespace by ID.
    fn find_ns(&self, ns_id: u64) -> Result<usize> {
        self.namespaces
            .iter()
            .position(|n| n.state == NsState::Active && n.id == ns_id)
            .ok_or(Error::NotFound)
    }

    /// Validate ID map entries for overlaps and zero counts.
    fn validate_map_entries(&self, entries: &[IdMapEntry]) -> Result<()> {
        for entry in entries {
            if entry.count == 0 {
                return Err(Error::InvalidArgument);
            }
        }
        // Check for overlapping ns_id ranges.
        for i in 0..entries.len() {
            let a = &entries[i];
            for b in &entries[i + 1..] {
                let a_end = a.ns_id + a.count;
                let b_end = b.ns_id + b.count;
                if a.ns_id < b_end && b.ns_id < a_end {
                    return Err(Error::InvalidArgument);
                }
            }
        }
        Ok(())
    }
}
