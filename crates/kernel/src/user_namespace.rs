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

/// `CAP_SETGID` capability index (Linux value; see
/// `crate::capability::CAP_SETGID`). Required in the parent namespace to
/// write a GID map with more than the single self-map entry.
const CAP_SETGID: u32 = 6;

/// `CAP_SETUID` capability index (Linux value; see
/// `crate::capability::CAP_SETUID`). Required in the parent namespace to
/// write a UID map with more than the single self-map entry.
const CAP_SETUID: u32 = 7;

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
    ///
    /// Uses subtraction (`id - base`) rather than `base + count` so the
    /// bound test cannot overflow when `ns_id + count` would exceed
    /// `u32::MAX`. Entries that would overflow are rejected at write
    /// time by [`UserNsTable::validate_map_entries`].
    fn contains_ns_id(&self, id: u32) -> bool {
        self.count > 0 && id >= self.ns_id && (id - self.ns_id) < self.count
    }

    /// Check if a host ID falls within this range.
    ///
    /// Overflow-safe: see [`IdMapEntry::contains_ns_id`].
    fn contains_host_id(&self, id: u32) -> bool {
        self.count > 0 && id >= self.host_id && (id - self.host_id) < self.count
    }

    /// Map a namespace ID to a host ID.
    ///
    /// Only valid after [`IdMapEntry::contains_ns_id`] returned true, which
    /// guarantees `ns_id >= self.ns_id` and the offset is `< count`. The host
    /// base plus offset is computed with `saturating_add`; validation rejects
    /// entries whose host range would overflow, so saturation never triggers
    /// for an in-range id.
    fn ns_to_host(&self, ns_id: u32) -> u32 {
        self.host_id.saturating_add(ns_id - self.ns_id)
    }

    /// Map a host ID to a namespace ID.
    ///
    /// Only valid after [`IdMapEntry::contains_host_id`] returned true. See
    /// [`IdMapEntry::ns_to_host`] for the overflow argument.
    fn host_to_ns(&self, host_id: u32) -> u32 {
        self.ns_id.saturating_add(host_id - self.host_id)
    }

    /// Exclusive end of the namespace-ID range, or `None` if it would
    /// overflow `u32::MAX`.
    fn ns_end(&self) -> Option<u32> {
        self.ns_id.checked_add(self.count)
    }

    /// Exclusive end of the host-ID range, or `None` if it would overflow
    /// `u32::MAX`.
    fn host_end(&self) -> Option<u32> {
        self.host_id.checked_add(self.count)
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
        // Do NOT grant blanket capabilities to the namespace owner. The
        // previous `full()` grant, combined with `ns_capable` reading this
        // field, made every owner all-powerful (CVE-class authority
        // confusion). Capability decisions now derive from the subject's
        // own effective set; this field is left empty so no stale state
        // can re-introduce that bypass.
        ns.owner_caps = NsCapSet::empty();
        ns.ref_count = 1;
        ns.state = NsState::Active;
        self.stats.total_created += 1;
        self.stats.active_count += 1;
        Ok(ns_id)
    }

    /// Write UID map entries for a user namespace.
    ///
    /// Can only be written once (before any process uses the ns).
    ///
    /// Authorization (modelled on Linux `new_idmap_permitted` /
    /// `map_write`): the write is permitted only if the requested host
    /// ranges are projectable by the caller. `caller_uid` is the writer's
    /// host UID and `caller_caps` its effective capability set. A
    /// privileged writer (holds `CAP_SETUID` in the **parent** namespace
    /// per [`UserNsTable::ns_capable`]) may install any ranges that are a
    /// subset of the parent's own UID map. An unprivileged writer may
    /// install only the single self-map entry (`count == 1`,
    /// `host_id == caller_uid`). Unauthorized writes return
    /// `Error::PermissionDenied`.
    pub fn write_uid_map(
        &mut self,
        ns_id: u64,
        caller_uid: u32,
        caller_caps: &[u64; CAP_WORDS],
        entries: &[IdMapEntry],
    ) -> Result<()> {
        if entries.is_empty() || entries.len() > MAX_ID_MAP_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        let idx = self.find_ns(ns_id)?;
        if self.namespaces[idx].uid_map_count > 0 {
            return Err(Error::AlreadyExists);
        }
        self.validate_map_entries(entries)?;
        self.authorize_map_write(ns_id, caller_uid, caller_caps, CAP_SETUID, entries, false)?;
        let ns = &mut self.namespaces[idx];
        for (i, entry) in entries.iter().enumerate() {
            ns.uid_map[i] = *entry;
        }
        ns.uid_map_count = entries.len() as u32;
        self.stats.total_uid_maps += 1;
        Ok(())
    }

    /// Write GID map entries for a user namespace.
    ///
    /// Authorization mirrors [`UserNsTable::write_uid_map`] but gates on
    /// `CAP_SETGID` and validates ranges against the parent's GID map.
    pub fn write_gid_map(
        &mut self,
        ns_id: u64,
        caller_uid: u32,
        caller_caps: &[u64; CAP_WORDS],
        entries: &[IdMapEntry],
    ) -> Result<()> {
        if entries.is_empty() || entries.len() > MAX_ID_MAP_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        let idx = self.find_ns(ns_id)?;
        if self.namespaces[idx].gid_map_count > 0 {
            return Err(Error::AlreadyExists);
        }
        self.validate_map_entries(entries)?;
        self.authorize_map_write(ns_id, caller_uid, caller_caps, CAP_SETGID, entries, true)?;
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

    /// Check if a subject holds a capability within a target namespace.
    ///
    /// Implements the Linux `ns_capable` rule with the credential inputs
    /// that are reachable here. The capability is granted only if **all**
    /// of the following hold:
    ///
    /// 1. The subject's user namespace (`caller_ns_id`) is an
    ///    ancestor-or-equal of `target_ns_id` (hierarchy walk), and
    /// 2. the subject's *effective* capability set (`subject_caps`, the
    ///    calling thread's effective cap words — **not** the namespace's
    ///    stored `owner_caps`) raises `cap`.
    ///
    /// As an owner shortcut, a subject acting in the target namespace
    /// itself (`caller_ns_id == target_ns_id`) whose `subject_euid`
    /// equals the namespace `owner_uid` is treated as holding `cap`,
    /// matching `cap_capable()`'s owner grant — but only for the
    /// namespace it owns, never for arbitrary descendants.
    ///
    /// The previous implementation returned the namespace's static
    /// `owner_caps` (always `full()`), which granted every capability to
    /// any thread routed through an ancestor ns regardless of that
    /// thread's real privileges. That bypass is removed here.
    pub fn ns_capable(
        &mut self,
        target_ns_id: u64,
        caller_ns_id: u64,
        subject_euid: u32,
        subject_caps: &[u64; CAP_WORDS],
        cap: u32,
    ) -> Result<bool> {
        self.stats.total_cap_checks += 1;
        let subject = NsCapSet {
            bits: *subject_caps,
        };
        // The subject must actually hold the effective capability.
        if !subject.has(cap) {
            // Owner shortcut: owner of the *target* ns acting within it.
            let owner_match = if caller_ns_id == target_ns_id {
                let idx = self.find_ns(target_ns_id)?;
                self.namespaces[idx].owner_uid == subject_euid
            } else {
                false
            };
            if !owner_match {
                return Ok(false);
            }
        }
        // Walk from target up to root, requiring caller's ns to be an
        // ancestor-or-equal of the target.
        let mut current_id = target_ns_id;
        loop {
            if current_id == caller_ns_id {
                return Ok(true);
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
        self.namespaces[idx].ref_count = self.namespaces[idx].ref_count.saturating_add(1);
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

    /// Validate ID map entries for zero counts, range overflow, and
    /// overlaps in both the namespace-ID and host-ID dimensions.
    ///
    /// Range arithmetic uses `checked_add`: any entry whose `[base,
    /// base + count)` interval would wrap past `u32::MAX` is rejected with
    /// `Error::InvalidArgument`. This prevents a wrapped end value from
    /// defeating the overlap test (which would otherwise admit aliased
    /// maps) and guarantees the subtraction-based `contains_*` /
    /// `*_to_*` helpers are exact for every accepted entry.
    fn validate_map_entries(&self, entries: &[IdMapEntry]) -> Result<()> {
        for entry in entries {
            if entry.count == 0 {
                return Err(Error::InvalidArgument);
            }
            // Reject ranges that wrap past u32::MAX in either dimension.
            if entry.ns_end().is_none() || entry.host_end().is_none() {
                return Err(Error::InvalidArgument);
            }
        }
        // Check for overlapping ranges in both the ns_id and host_id
        // dimensions. Ends are guaranteed non-overflowing by the loop above.
        for i in 0..entries.len() {
            let a = &entries[i];
            for b in &entries[i + 1..] {
                let (Some(a_ns_end), Some(b_ns_end)) = (a.ns_end(), b.ns_end()) else {
                    return Err(Error::InvalidArgument);
                };
                if a.ns_id < b_ns_end && b.ns_id < a_ns_end {
                    return Err(Error::InvalidArgument);
                }
                let (Some(a_host_end), Some(b_host_end)) = (a.host_end(), b.host_end()) else {
                    return Err(Error::InvalidArgument);
                };
                if a.host_id < b_host_end && b.host_id < a_host_end {
                    return Err(Error::InvalidArgument);
                }
            }
        }
        Ok(())
    }

    /// Authorize an ID-map write against the kernel mapping policy.
    ///
    /// `is_gid` selects which map (uid vs gid) of the **parent** namespace
    /// the requested host ranges are validated against. `setid_cap` is the
    /// capability (`CAP_SETUID`/`CAP_SETGID`) required for a multi-entry or
    /// non-self map. Returns `Error::PermissionDenied` on any policy
    /// failure.
    ///
    /// Policy (subset of Linux `new_idmap_permitted`):
    ///
    /// * **Privileged path** — the caller holds `setid_cap` in the parent
    ///   namespace (or, for the init ns, in the init ns itself) per
    ///   [`UserNsTable::ns_capable`]. Every requested host range must still
    ///   be a subset of the parent's existing map
    ///   ([`UserNsTable::parent_owns_ranges`]), so a child can never
    ///   project host IDs the parent itself cannot.
    /// * **Unprivileged path** — permitted only for a single entry with
    ///   `count == 1` whose `host_id` equals the writer's own
    ///   `caller_uid`, i.e. a process mapping just its own identity. This
    ///   range must likewise be owned by the parent.
    fn authorize_map_write(
        &mut self,
        ns_id: u64,
        caller_uid: u32,
        caller_caps: &[u64; CAP_WORDS],
        setid_cap: u32,
        entries: &[IdMapEntry],
        is_gid: bool,
    ) -> Result<()> {
        let idx = self.find_ns(ns_id)?;
        let parent_id = self.namespaces[idx].parent_id;
        // Privilege for a map write requires the effective `setid_cap`
        // *bit* held in the parent namespace. The owner-euid shortcut of
        // `ns_capable` is deliberately NOT used here: granting CAP_SETUID
        // to a namespace owner merely because it created the ns is exactly
        // the bypass this fix removes. For the init ns (parent_id == 0)
        // there is no parent, so only the unprivileged self-map path below
        // can apply.
        let subject = NsCapSet { bits: *caller_caps };
        let privileged = parent_id != 0
            && subject.has(setid_cap)
            && self.ns_capable(parent_id, parent_id, caller_uid, caller_caps, setid_cap)?;
        if !privileged {
            // Unprivileged: only the writer's own single identity entry.
            let self_map =
                entries.len() == 1 && entries[0].count == 1 && entries[0].host_id == caller_uid;
            if !self_map {
                return Err(Error::PermissionDenied);
            }
        }
        // In all cases the host ranges must be projectable by the parent.
        if !self.parent_owns_ranges(parent_id, entries, is_gid)? {
            return Err(Error::PermissionDenied);
        }
        Ok(())
    }

    /// Check that every requested host range is a subset of the parent
    /// namespace's existing ID map (uid or gid, per `is_gid`).
    ///
    /// The initial user namespace (or `parent_id == 0`) owns the entire
    /// host ID space by definition, so any range is permitted there. For a
    /// nested parent, each `[host_id, host_id + count)` interval must be
    /// fully covered by a single configured parent entry; ranges are not
    /// split across parent entries, matching the contiguous-map model used
    /// here. Fail-closed: a nested parent with no configured map owns
    /// nothing.
    fn parent_owns_ranges(
        &self,
        parent_id: u64,
        entries: &[IdMapEntry],
        is_gid: bool,
    ) -> Result<bool> {
        // init_user_ns / no parent owns the full host ID space.
        if parent_id == 0 || parent_id == INIT_USER_NS_ID {
            return Ok(true);
        }
        let pidx = self.find_ns(parent_id)?;
        let parent = &self.namespaces[pidx];
        let (map, count) = if is_gid {
            (&parent.gid_map, parent.gid_map_count as usize)
        } else {
            (&parent.uid_map, parent.uid_map_count as usize)
        };
        if count == 0 {
            return Ok(false);
        }
        for entry in entries {
            // `count` is validated non-zero and non-overflowing already, so
            // `count - 1` and the saturating add cannot wrap into a smaller
            // value for an accepted entry.
            let last = entry.host_id.saturating_add(entry.count - 1);
            let covered = map[..count].iter().any(|p| {
                p.count > 0 && p.contains_host_id(entry.host_id) && p.contains_host_id(last)
            });
            if !covered {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
