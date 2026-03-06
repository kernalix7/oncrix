// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Namespace proxy (nsproxy) management.
//!
//! Each task holds a reference to an `NsProxy` that aggregates pointers
//! to the task's active namespaces (PID, mount, network, UTS, IPC, user,
//! cgroup, time). When a task calls `clone()` with namespace flags or
//! `unshare()`, the kernel creates a new `NsProxy` (possibly sharing
//! some namespaces with the old one).
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                       NsProxyTable                               │
//! │                                                                  │
//! │  [NsProxy; MAX_PROXIES]  — all live proxy objects                │
//! │  ┌────────────────────────────────────────────────────────────┐  │
//! │  │  NsProxy                                                   │  │
//! │  │    pid_ns_id, mnt_ns_id, net_ns_id, uts_ns_id …           │  │
//! │  │    ref_count — number of tasks sharing this proxy          │  │
//! │  │    owner_pid — task that created this proxy                │  │
//! │  │    NsProxyFlags — which namespaces differ from parent      │  │
//! │  └────────────────────────────────────────────────────────────┘  │
//! │                                                                  │
//! │  NamespaceEntry [MAX_NAMESPACES] — individual namespace objects  │
//! │  NsProxyStats — global counters                                  │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Lifecycle
//!
//! 1. `fork()` without namespace flags → child gets parent's `NsProxy`
//!    (ref_count++).
//! 2. `clone(CLONE_NEW*)` → `copy_nsproxy()` creates a new proxy,
//!    replacing the flagged namespace IDs with fresh ones.
//! 3. `unshare(CLONE_NEW*)` → same as clone but in-place for the
//!    calling task.
//! 4. `setns(fd, nstype)` → switch a single namespace in the proxy.
//! 5. On task exit → `put_nsproxy()` decrements ref_count, freeing
//!    the proxy when it reaches zero.
//!
//! # Reference
//!
//! Linux `kernel/nsproxy.c`, `include/linux/nsproxy.h`,
//! `include/uapi/linux/sched.h` (CLONE_NEW* flags).

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of nsproxy objects in the system.
const MAX_PROXIES: usize = 256;

/// Maximum individual namespace objects tracked globally.
const MAX_NAMESPACES: usize = 512;

/// Maximum name length for a namespace.
const MAX_NS_NAME_LEN: usize = 32;

/// Maximum tasks that can share a single nsproxy.
const MAX_REF_COUNT: u64 = 1_000_000;

/// Number of namespace types supported.
const NS_TYPE_COUNT: usize = 8;

// ── Clone flags ─────────────────────────────────────────────────────────────

/// Clone flag for a new PID namespace.
pub const CLONE_NEWPID: u64 = 1 << 0;

/// Clone flag for a new mount namespace.
pub const CLONE_NEWNS: u64 = 1 << 1;

/// Clone flag for a new network namespace.
pub const CLONE_NEWNET: u64 = 1 << 2;

/// Clone flag for a new UTS namespace.
pub const CLONE_NEWUTS: u64 = 1 << 3;

/// Clone flag for a new IPC namespace.
pub const CLONE_NEWIPC: u64 = 1 << 4;

/// Clone flag for a new user namespace.
pub const CLONE_NEWUSER: u64 = 1 << 5;

/// Clone flag for a new cgroup namespace.
pub const CLONE_NEWCGROUP: u64 = 1 << 6;

/// Clone flag for a new time namespace.
pub const CLONE_NEWTIME: u64 = 1 << 7;

/// Mask of all CLONE_NEW* flags.
const CLONE_NEW_ALL: u64 = CLONE_NEWPID
    | CLONE_NEWNS
    | CLONE_NEWNET
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWUSER
    | CLONE_NEWCGROUP
    | CLONE_NEWTIME;

// ── NamespaceType ───────────────────────────────────────────────────────────

/// Type of Linux namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceType {
    /// PID namespace — isolated PID number space.
    Pid,
    /// Mount namespace — isolated mount table.
    Mount,
    /// Network namespace — isolated network stack.
    Network,
    /// UTS namespace — isolated hostname/domainname.
    Uts,
    /// IPC namespace — isolated SysV IPC / POSIX MQ.
    Ipc,
    /// User namespace — isolated UID/GID mappings.
    User,
    /// Cgroup namespace — isolated cgroup root.
    Cgroup,
    /// Time namespace — isolated CLOCK_MONOTONIC / CLOCK_BOOTTIME.
    Time,
}

impl NamespaceType {
    /// Convert to an index (0..NS_TYPE_COUNT).
    const fn as_index(self) -> usize {
        match self {
            Self::Pid => 0,
            Self::Mount => 1,
            Self::Network => 2,
            Self::Uts => 3,
            Self::Ipc => 4,
            Self::User => 5,
            Self::Cgroup => 6,
            Self::Time => 7,
        }
    }

    /// Get the corresponding CLONE_NEW* flag.
    const fn clone_flag(self) -> u64 {
        match self {
            Self::Pid => CLONE_NEWPID,
            Self::Mount => CLONE_NEWNS,
            Self::Network => CLONE_NEWNET,
            Self::Uts => CLONE_NEWUTS,
            Self::Ipc => CLONE_NEWIPC,
            Self::User => CLONE_NEWUSER,
            Self::Cgroup => CLONE_NEWCGROUP,
            Self::Time => CLONE_NEWTIME,
        }
    }

    /// All namespace types as an array for iteration.
    const ALL: [Self; NS_TYPE_COUNT] = [
        Self::Pid,
        Self::Mount,
        Self::Network,
        Self::Uts,
        Self::Ipc,
        Self::User,
        Self::Cgroup,
        Self::Time,
    ];
}

// ── NsState ─────────────────────────────────────────────────────────────────

/// Lifecycle state of a namespace object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NsState {
    /// Slot is free.
    Free,
    /// Namespace is active.
    Active,
    /// Namespace is being torn down.
    Dying,
    /// Namespace has been destroyed.
    Dead,
}

impl Default for NsState {
    fn default() -> Self {
        Self::Free
    }
}

// ── NamespaceEntry ──────────────────────────────────────────────────────────

/// A single namespace object in the global namespace table.
#[derive(Debug, Clone, Copy)]
pub struct NamespaceEntry {
    /// Unique identifier for this namespace.
    id: u64,
    /// Type of namespace.
    ns_type: NamespaceType,
    /// Current lifecycle state.
    state: NsState,
    /// Reference count (number of nsproxy objects using this ns).
    ref_count: u64,
    /// Creator process ID.
    creator_pid: u64,
    /// Parent namespace ID (0 if root).
    parent_id: u64,
    /// Human-readable name.
    name: [u8; MAX_NS_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Creation timestamp (nanoseconds since boot).
    created_ns: u64,
    /// Flags specific to this namespace type.
    type_flags: u32,
}

impl NamespaceEntry {
    /// Create an empty namespace entry.
    const fn new() -> Self {
        Self {
            id: 0,
            ns_type: NamespaceType::Pid,
            state: NsState::Free,
            ref_count: 0,
            creator_pid: 0,
            parent_id: 0,
            name: [0u8; MAX_NS_NAME_LEN],
            name_len: 0,
            created_ns: 0,
            type_flags: 0,
        }
    }

    /// Check whether this slot is free.
    fn is_free(&self) -> bool {
        matches!(self.state, NsState::Free | NsState::Dead)
    }

    /// Get the namespace ID.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Get the namespace type.
    pub fn ns_type(&self) -> NamespaceType {
        self.ns_type
    }

    /// Get the reference count.
    pub fn ref_count(&self) -> u64 {
        self.ref_count
    }
}

// ── NsProxyFlags ────────────────────────────────────────────────────────────

/// Flags indicating which namespaces differ from the init proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NsProxyFlags(pub u64);

impl NsProxyFlags {
    /// No special flags.
    pub const NONE: Self = Self(0);

    /// Check whether a specific namespace type is flagged.
    pub fn has(self, ns_type: NamespaceType) -> bool {
        self.0 & ns_type.clone_flag() != 0
    }

    /// Set a namespace type flag.
    pub fn set(&mut self, ns_type: NamespaceType) {
        self.0 |= ns_type.clone_flag();
    }

    /// Clear a namespace type flag.
    pub fn clear(&mut self, ns_type: NamespaceType) {
        self.0 &= !ns_type.clone_flag();
    }

    /// Count how many namespace types are flagged.
    pub fn count(self) -> usize {
        NamespaceType::ALL.iter().filter(|t| self.has(**t)).count()
    }
}

// ── NsProxyState ────────────────────────────────────────────────────────────

/// Lifecycle state of an nsproxy object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NsProxyState {
    /// Slot is free.
    Free,
    /// Proxy is active.
    Active,
    /// Proxy is being copied (transient state during clone).
    Copying,
    /// Proxy has been released.
    Released,
}

impl Default for NsProxyState {
    fn default() -> Self {
        Self::Free
    }
}

// ── NsProxy ─────────────────────────────────────────────────────────────────

/// A namespace proxy — aggregates namespace IDs for a task.
///
/// Each task holds a reference to one `NsProxy`. Multiple tasks can
/// share the same proxy. The namespace IDs stored here point into the
/// global `NamespaceEntry` table.
#[derive(Debug, Clone, Copy)]
pub struct NsProxy {
    /// Unique proxy identifier.
    id: u64,
    /// Current state.
    state: NsProxyState,
    /// Reference count (tasks sharing this proxy).
    ref_count: u64,
    /// PID of the task that created this proxy.
    owner_pid: u64,
    /// Namespace IDs indexed by `NamespaceType::as_index()`.
    ns_ids: [u64; NS_TYPE_COUNT],
    /// Flags indicating which namespaces differ from init.
    flags: NsProxyFlags,
    /// Parent proxy ID (the proxy this was cloned from).
    parent_proxy_id: u64,
    /// Creation timestamp.
    created_ns: u64,
}

impl NsProxy {
    /// Create an empty proxy slot.
    const fn new() -> Self {
        Self {
            id: 0,
            state: NsProxyState::Free,
            ref_count: 0,
            owner_pid: 0,
            ns_ids: [0u64; NS_TYPE_COUNT],
            flags: NsProxyFlags::NONE,
            parent_proxy_id: 0,
            created_ns: 0,
        }
    }

    /// Check whether this slot is free.
    fn is_free(&self) -> bool {
        matches!(self.state, NsProxyState::Free | NsProxyState::Released)
    }

    /// Get the namespace ID for a given type.
    pub fn ns_id(&self, ns_type: NamespaceType) -> u64 {
        self.ns_ids[ns_type.as_index()]
    }

    /// Set the namespace ID for a given type.
    fn set_ns_id(&mut self, ns_type: NamespaceType, id: u64) {
        self.ns_ids[ns_type.as_index()] = id;
    }

    /// Get the proxy identifier.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Get the reference count.
    pub fn ref_count(&self) -> u64 {
        self.ref_count
    }

    /// Get the flags.
    pub fn flags(&self) -> NsProxyFlags {
        self.flags
    }
}

// ── NsProxyStats ────────────────────────────────────────────────────────────

/// Global statistics for the nsproxy subsystem.
#[derive(Debug, Clone, Copy)]
pub struct NsProxyStats {
    /// Total proxies created.
    pub proxies_created: u64,
    /// Total proxies released.
    pub proxies_released: u64,
    /// Total namespaces created.
    pub namespaces_created: u64,
    /// Total namespaces destroyed.
    pub namespaces_destroyed: u64,
    /// Total clone operations.
    pub clone_ops: u64,
    /// Total unshare operations.
    pub unshare_ops: u64,
    /// Total setns operations.
    pub setns_ops: u64,
    /// Failed operations.
    pub failed_ops: u64,
    /// Current active proxy count.
    pub active_proxies: u64,
    /// Current active namespace count.
    pub active_namespaces: u64,
}

impl NsProxyStats {
    /// Create zeroed statistics.
    const fn new() -> Self {
        Self {
            proxies_created: 0,
            proxies_released: 0,
            namespaces_created: 0,
            namespaces_destroyed: 0,
            clone_ops: 0,
            unshare_ops: 0,
            setns_ops: 0,
            failed_ops: 0,
            active_proxies: 0,
            active_namespaces: 0,
        }
    }
}

// ── NsProxyTable ────────────────────────────────────────────────────────────

/// Top-level namespace proxy management subsystem.
///
/// Tracks all `NsProxy` objects and the global namespace table.
/// Provides operations for `clone()`, `unshare()`, `setns()`,
/// and lifecycle management.
pub struct NsProxyTable {
    /// Proxy objects.
    proxies: [NsProxy; MAX_PROXIES],
    /// Global namespace entries.
    namespaces: [NamespaceEntry; MAX_NAMESPACES],
    /// Next proxy ID to assign.
    next_proxy_id: u64,
    /// Next namespace ID to assign.
    next_ns_id: u64,
    /// The init nsproxy index (always slot 0).
    init_proxy_idx: usize,
    /// Global statistics.
    stats: NsProxyStats,
    /// Current timestamp.
    now_ns: u64,
}

impl NsProxyTable {
    /// Create a new nsproxy table with the init proxy pre-created.
    pub const fn new() -> Self {
        Self {
            proxies: [const { NsProxy::new() }; MAX_PROXIES],
            namespaces: [const { NamespaceEntry::new() }; MAX_NAMESPACES],
            next_proxy_id: 1,
            next_ns_id: 1,
            init_proxy_idx: 0,
            stats: NsProxyStats::new(),
            now_ns: 0,
        }
    }

    /// Update the internal time reference.
    pub fn set_time_ns(&mut self, ns: u64) {
        self.now_ns = ns;
    }

    /// Get the global statistics.
    pub fn stats(&self) -> &NsProxyStats {
        &self.stats
    }

    // ── Init proxy setup ────────────────────────────────────────────

    /// Set up the init (root) nsproxy with default namespaces.
    ///
    /// Must be called once during early boot. Creates one namespace
    /// per type and assigns them to proxy slot 0.
    pub fn init_boot(&mut self) -> Result<usize> {
        let proxy_idx = 0;
        self.proxies[proxy_idx].id = self.next_proxy_id;
        self.next_proxy_id += 1;
        self.proxies[proxy_idx].state = NsProxyState::Active;
        self.proxies[proxy_idx].ref_count = 1;
        self.proxies[proxy_idx].owner_pid = 1; // init
        self.proxies[proxy_idx].created_ns = self.now_ns;

        // Create one root namespace per type.
        for ns_type in &NamespaceType::ALL {
            let ns_idx = self.alloc_namespace(
                *ns_type, 1, // creator = init
                0, // no parent
            )?;
            let ns_id = self.namespaces[ns_idx].id;
            self.proxies[proxy_idx].ns_ids[ns_type.as_index()] = ns_id;
        }

        self.stats.proxies_created += 1;
        self.stats.active_proxies += 1;
        self.init_proxy_idx = proxy_idx;
        Ok(proxy_idx)
    }

    // ── Proxy reference counting ────────────────────────────────────

    /// Increment the reference count on a proxy (fork without new ns).
    pub fn get_nsproxy(&mut self, proxy_idx: usize) -> Result<()> {
        if proxy_idx >= MAX_PROXIES {
            return Err(Error::InvalidArgument);
        }
        let proxy = &mut self.proxies[proxy_idx];
        if proxy.is_free() {
            return Err(Error::NotFound);
        }
        if proxy.ref_count >= MAX_REF_COUNT {
            return Err(Error::OutOfMemory);
        }
        proxy.ref_count += 1;
        Ok(())
    }

    /// Decrement the reference count; free the proxy when it reaches 0.
    pub fn put_nsproxy(&mut self, proxy_idx: usize) -> Result<()> {
        if proxy_idx >= MAX_PROXIES {
            return Err(Error::InvalidArgument);
        }
        let proxy = &mut self.proxies[proxy_idx];
        if proxy.is_free() {
            return Err(Error::NotFound);
        }
        proxy.ref_count = proxy.ref_count.saturating_sub(1);
        if proxy.ref_count == 0 {
            self.release_proxy(proxy_idx)?;
        }
        Ok(())
    }

    // ── Clone / copy_nsproxy ────────────────────────────────────────

    /// Copy an nsproxy, creating new namespaces for each flag set.
    ///
    /// This is the core of `clone(CLONE_NEW*)`. The new proxy shares
    /// namespaces that are not flagged and creates fresh ones for
    /// those that are.
    ///
    /// Returns the index of the new proxy.
    pub fn copy_nsproxy(&mut self, src_idx: usize, clone_flags: u64, pid: u64) -> Result<usize> {
        if src_idx >= MAX_PROXIES {
            return Err(Error::InvalidArgument);
        }
        if self.proxies[src_idx].is_free() {
            return Err(Error::NotFound);
        }
        if clone_flags & !CLONE_NEW_ALL != 0 {
            return Err(Error::InvalidArgument);
        }

        let new_idx = self.alloc_proxy(pid)?;

        // Copy all namespace IDs from source.
        for ns_type in &NamespaceType::ALL {
            let idx = ns_type.as_index();
            self.proxies[new_idx].ns_ids[idx] = self.proxies[src_idx].ns_ids[idx];
        }

        // For each flagged type, create a new namespace.
        for ns_type in &NamespaceType::ALL {
            if clone_flags & ns_type.clone_flag() != 0 {
                let parent_ns_id = self.proxies[src_idx].ns_ids[ns_type.as_index()];
                let ns_idx = self.alloc_namespace(*ns_type, pid, parent_ns_id)?;
                self.proxies[new_idx].ns_ids[ns_type.as_index()] = self.namespaces[ns_idx].id;
                self.proxies[new_idx].flags.set(*ns_type);

                // Increment ref on the new namespace.
                self.namespaces[ns_idx].ref_count += 1;
            } else {
                // Sharing — increment ref on the existing namespace.
                let ns_id = self.proxies[new_idx].ns_ids[ns_type.as_index()];
                if let Some(ns_idx) = self.find_namespace(ns_id) {
                    self.namespaces[ns_idx].ref_count += 1;
                }
            }
        }

        self.proxies[new_idx].parent_proxy_id = self.proxies[src_idx].id;
        self.stats.clone_ops += 1;
        Ok(new_idx)
    }

    // ── Unshare ─────────────────────────────────────────────────────

    /// Unshare namespaces for a task, replacing flagged namespaces
    /// in its existing proxy with new ones.
    ///
    /// If the proxy has ref_count > 1, a new proxy is created first.
    /// Returns the (possibly new) proxy index.
    pub fn unshare(&mut self, proxy_idx: usize, flags: u64, pid: u64) -> Result<usize> {
        if proxy_idx >= MAX_PROXIES {
            return Err(Error::InvalidArgument);
        }
        if self.proxies[proxy_idx].is_free() {
            return Err(Error::NotFound);
        }
        if flags & !CLONE_NEW_ALL != 0 {
            return Err(Error::InvalidArgument);
        }
        if flags == 0 {
            return Ok(proxy_idx);
        }

        // If shared, must copy first.
        let target_idx = if self.proxies[proxy_idx].ref_count > 1 {
            let new_idx = self.copy_nsproxy(proxy_idx, 0, pid)?;
            self.put_nsproxy(proxy_idx)?;
            new_idx
        } else {
            proxy_idx
        };

        // Now replace flagged namespaces.
        for ns_type in &NamespaceType::ALL {
            if flags & ns_type.clone_flag() != 0 {
                let old_ns_id = self.proxies[target_idx].ns_ids[ns_type.as_index()];

                // Decrement old namespace ref.
                if let Some(old_idx) = self.find_namespace(old_ns_id) {
                    self.decrement_ns_ref(old_idx);
                }

                // Create new namespace.
                let ns_idx = self.alloc_namespace(*ns_type, pid, old_ns_id)?;
                self.proxies[target_idx].ns_ids[ns_type.as_index()] = self.namespaces[ns_idx].id;
                self.namespaces[ns_idx].ref_count += 1;
                self.proxies[target_idx].flags.set(*ns_type);
            }
        }

        self.stats.unshare_ops += 1;
        Ok(target_idx)
    }

    // ── Setns ───────────────────────────────────────────────────────

    /// Switch a single namespace for a task's proxy.
    ///
    /// The task's proxy is updated to point to `target_ns_id` for the
    /// given namespace type. If the proxy is shared, it is copied first.
    pub fn setns(
        &mut self,
        proxy_idx: usize,
        ns_type: NamespaceType,
        target_ns_id: u64,
        pid: u64,
    ) -> Result<usize> {
        if proxy_idx >= MAX_PROXIES {
            return Err(Error::InvalidArgument);
        }
        if self.proxies[proxy_idx].is_free() {
            return Err(Error::NotFound);
        }

        // Verify target namespace exists and is the right type.
        let target_ns_idx = self.find_namespace(target_ns_id).ok_or(Error::NotFound)?;
        if self.namespaces[target_ns_idx].ns_type != ns_type {
            return Err(Error::InvalidArgument);
        }
        if !matches!(self.namespaces[target_ns_idx].state, NsState::Active) {
            return Err(Error::NotFound);
        }

        // If shared proxy, copy first.
        let target_proxy = if self.proxies[proxy_idx].ref_count > 1 {
            let new_idx = self.copy_nsproxy(proxy_idx, 0, pid)?;
            self.put_nsproxy(proxy_idx)?;
            new_idx
        } else {
            proxy_idx
        };

        // Decrement old namespace ref.
        let old_ns_id = self.proxies[target_proxy].ns_ids[ns_type.as_index()];
        if let Some(old_idx) = self.find_namespace(old_ns_id) {
            self.decrement_ns_ref(old_idx);
        }

        // Set new namespace.
        self.proxies[target_proxy].ns_ids[ns_type.as_index()] = target_ns_id;
        self.namespaces[target_ns_idx].ref_count += 1;

        self.stats.setns_ops += 1;
        Ok(target_proxy)
    }

    // ── Query ───────────────────────────────────────────────────────

    /// Get a proxy by index.
    pub fn proxy(&self, idx: usize) -> Result<&NsProxy> {
        if idx >= MAX_PROXIES {
            return Err(Error::InvalidArgument);
        }
        if self.proxies[idx].is_free() {
            return Err(Error::NotFound);
        }
        Ok(&self.proxies[idx])
    }

    /// Get a namespace entry by ID.
    pub fn namespace_by_id(&self, id: u64) -> Result<&NamespaceEntry> {
        self.find_namespace(id)
            .map(|idx| &self.namespaces[idx])
            .ok_or(Error::NotFound)
    }

    /// Get the init proxy index.
    pub fn init_proxy_idx(&self) -> usize {
        self.init_proxy_idx
    }

    /// Count active proxies.
    pub fn active_proxy_count(&self) -> usize {
        self.proxies
            .iter()
            .filter(|p| matches!(p.state, NsProxyState::Active))
            .count()
    }

    /// Count active namespaces of a given type.
    pub fn active_ns_count(&self, ns_type: NamespaceType) -> usize {
        self.namespaces
            .iter()
            .filter(|n| matches!(n.state, NsState::Active) && n.ns_type == ns_type)
            .count()
    }

    /// Check whether two proxy indices share a given namespace type.
    pub fn shares_ns(&self, a: usize, b: usize, ns_type: NamespaceType) -> Result<bool> {
        if a >= MAX_PROXIES || b >= MAX_PROXIES {
            return Err(Error::InvalidArgument);
        }
        if self.proxies[a].is_free() || self.proxies[b].is_free() {
            return Err(Error::NotFound);
        }
        let idx = ns_type.as_index();
        Ok(self.proxies[a].ns_ids[idx] == self.proxies[b].ns_ids[idx])
    }

    // ── Internal helpers ────────────────────────────────────────────

    /// Allocate a free proxy slot.
    fn alloc_proxy(&mut self, pid: u64) -> Result<usize> {
        let idx = self
            .proxies
            .iter()
            .position(|p| p.is_free())
            .ok_or(Error::OutOfMemory)?;

        self.proxies[idx] = NsProxy {
            id: self.next_proxy_id,
            state: NsProxyState::Active,
            ref_count: 1,
            owner_pid: pid,
            ns_ids: [0u64; NS_TYPE_COUNT],
            flags: NsProxyFlags::NONE,
            parent_proxy_id: 0,
            created_ns: self.now_ns,
        };
        self.next_proxy_id += 1;
        self.stats.proxies_created += 1;
        self.stats.active_proxies += 1;
        Ok(idx)
    }

    /// Release a proxy (set state to Released, decrement ns refs).
    fn release_proxy(&mut self, idx: usize) -> Result<()> {
        let proxy = &self.proxies[idx];
        if proxy.is_free() {
            return Err(Error::NotFound);
        }

        // Decrement ref on each namespace.
        let ns_ids = proxy.ns_ids;
        for ns_id in &ns_ids {
            if let Some(ns_idx) = self.find_namespace(*ns_id) {
                self.decrement_ns_ref(ns_idx);
            }
        }

        self.proxies[idx].state = NsProxyState::Released;
        self.stats.proxies_released += 1;
        self.stats.active_proxies = self.stats.active_proxies.saturating_sub(1);
        Ok(())
    }

    /// Allocate a new namespace entry.
    fn alloc_namespace(
        &mut self,
        ns_type: NamespaceType,
        creator_pid: u64,
        parent_id: u64,
    ) -> Result<usize> {
        let idx = self
            .namespaces
            .iter()
            .position(|n| n.is_free())
            .ok_or(Error::OutOfMemory)?;

        self.namespaces[idx] = NamespaceEntry {
            id: self.next_ns_id,
            ns_type,
            state: NsState::Active,
            ref_count: 0,
            creator_pid,
            parent_id,
            name: [0u8; MAX_NS_NAME_LEN],
            name_len: 0,
            created_ns: self.now_ns,
            type_flags: 0,
        };
        self.next_ns_id += 1;
        self.stats.namespaces_created += 1;
        self.stats.active_namespaces += 1;
        Ok(idx)
    }

    /// Find a namespace entry by ID.
    fn find_namespace(&self, id: u64) -> Option<usize> {
        if id == 0 {
            return None;
        }
        self.namespaces
            .iter()
            .position(|n| n.id == id && !n.is_free())
    }

    /// Decrement a namespace's ref count, destroying it if zero.
    fn decrement_ns_ref(&mut self, idx: usize) {
        let ns = &mut self.namespaces[idx];
        ns.ref_count = ns.ref_count.saturating_sub(1);
        if ns.ref_count == 0 && !matches!(ns.state, NsState::Free | NsState::Dead) {
            ns.state = NsState::Dead;
            self.stats.namespaces_destroyed += 1;
            self.stats.active_namespaces = self.stats.active_namespaces.saturating_sub(1);
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_boot() {
        let mut table = NsProxyTable::new();
        let idx = table.init_boot().unwrap();
        assert_eq!(idx, 0);
        assert_eq!(table.active_proxy_count(), 1);
        // All 8 namespace types should exist.
        for ns_type in &NamespaceType::ALL {
            assert!(table.active_ns_count(*ns_type) >= 1);
        }
    }

    #[test]
    fn test_clone_new_pid() {
        let mut table = NsProxyTable::new();
        table.init_boot().unwrap();
        let new_idx = table.copy_nsproxy(0, CLONE_NEWPID, 42).unwrap();
        assert_ne!(new_idx, 0);
        // PID ns should differ, others should be shared.
        assert!(!table.shares_ns(0, new_idx, NamespaceType::Pid).unwrap());
        assert!(table.shares_ns(0, new_idx, NamespaceType::Network).unwrap());
    }

    #[test]
    fn test_unshare() {
        let mut table = NsProxyTable::new();
        table.init_boot().unwrap();
        let new_idx = table.unshare(0, CLONE_NEWNET, 10).unwrap();
        // Since init proxy has ref_count=1, we reuse it.
        assert_eq!(new_idx, 0);
        assert_eq!(table.stats().unshare_ops, 1);
    }

    #[test]
    fn test_setns() {
        let mut table = NsProxyTable::new();
        table.init_boot().unwrap();
        let new_proxy = table.copy_nsproxy(0, CLONE_NEWUTS, 5).unwrap();
        let new_uts_id = table.proxy(new_proxy).unwrap().ns_id(NamespaceType::Uts);
        // setns back to the new UTS namespace.
        let result = table.setns(0, NamespaceType::Uts, new_uts_id, 1);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ref_counting() {
        let mut table = NsProxyTable::new();
        table.init_boot().unwrap();
        table.get_nsproxy(0).unwrap();
        assert_eq!(table.proxy(0).unwrap().ref_count(), 2);
        table.put_nsproxy(0).unwrap();
        assert_eq!(table.proxy(0).unwrap().ref_count(), 1);
    }
}
