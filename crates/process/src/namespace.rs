// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Linux-style namespace support for process isolation.
//!
//! Namespaces provide lightweight virtualization by isolating
//! kernel resources so that processes within a namespace see
//! their own independent view of mount points, PIDs, network,
//! IPC, hostname, user IDs, cgroups, and clocks.
//!
//! This module implements:
//! - [`NamespaceType`] — enumeration of supported namespace kinds
//! - [`NsFlags`] — bitmask flags for `clone`/`unshare` operations
//! - [`Namespace`] — base metadata shared by all namespace types
//! - Type-specific namespaces: [`PidNamespace`], [`MountNamespace`],
//!   [`UtsNamespace`], [`UserNamespace`]
//! - [`NamespaceSet`] — a process's complete namespace membership
//! - [`NamespaceRegistry`] — system-wide namespace management

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────

/// Maximum number of PID translation entries per PID namespace.
const MAX_PID_MAPPINGS: usize = 64;

/// Maximum number of mount points per mount namespace.
const MAX_MOUNTS: usize = 32;

/// Maximum length of UTS nodename/domainname (POSIX `_UTSNAME_LENGTH`).
const UTS_NAME_LEN: usize = 65;

/// Maximum number of UID/GID mapping entries per user namespace.
const MAX_ID_MAPPINGS: usize = 16;

/// Maximum number of namespaces managed by the global registry.
const MAX_NAMESPACES: usize = 128;

/// Number of distinct namespace types.
const NS_TYPE_COUNT: usize = 8;

// ── NsFlags bitmask ───────────────────────────────────────────────

/// Bitmask flags for namespace operations (`clone`, `unshare`).
///
/// Each flag requests creation of a new namespace of the
/// corresponding type. Multiple flags can be combined with
/// bitwise OR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NsFlags(u32);

impl NsFlags {
    /// Create a new mount namespace.
    pub const CLONE_NEWNS: Self = Self(1 << 0);
    /// Create a new PID namespace.
    pub const CLONE_NEWPID: Self = Self(1 << 1);
    /// Create a new network namespace.
    pub const CLONE_NEWNET: Self = Self(1 << 2);
    /// Create a new IPC namespace.
    pub const CLONE_NEWIPC: Self = Self(1 << 3);
    /// Create a new UTS namespace.
    pub const CLONE_NEWUTS: Self = Self(1 << 4);
    /// Create a new user namespace.
    pub const CLONE_NEWUSER: Self = Self(1 << 5);
    /// Create a new cgroup namespace.
    pub const CLONE_NEWCGROUP: Self = Self(1 << 6);
    /// Create a new time namespace.
    pub const CLONE_NEWTIME: Self = Self(1 << 7);

    /// Empty flags (no new namespaces requested).
    pub const EMPTY: Self = Self(0);

    /// Create flags from a raw `u32` value.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Return the raw `u32` value of these flags.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Return `true` if the given flag is set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Combine two flag sets with bitwise OR.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Return `true` if no flags are set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Return the flag corresponding to a [`NamespaceType`].
    pub const fn for_type(ns_type: NamespaceType) -> Self {
        match ns_type {
            NamespaceType::Mount => Self::CLONE_NEWNS,
            NamespaceType::Pid => Self::CLONE_NEWPID,
            NamespaceType::Net => Self::CLONE_NEWNET,
            NamespaceType::Ipc => Self::CLONE_NEWIPC,
            NamespaceType::Uts => Self::CLONE_NEWUTS,
            NamespaceType::User => Self::CLONE_NEWUSER,
            NamespaceType::Cgroup => Self::CLONE_NEWCGROUP,
            NamespaceType::Time => Self::CLONE_NEWTIME,
        }
    }
}

// ── NamespaceType enum ────────────────────────────────────────────

/// Enumeration of supported namespace types.
///
/// Each variant corresponds to a Linux namespace kind that isolates
/// a specific category of kernel resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NamespaceType {
    /// Mount namespace — isolates filesystem mount points.
    Mount = 0,
    /// PID namespace — isolates process ID number space.
    Pid = 1,
    /// Network namespace — isolates network stack.
    Net = 2,
    /// IPC namespace — isolates System V IPC and POSIX MQs.
    Ipc = 3,
    /// UTS namespace — isolates hostname and domain name.
    Uts = 4,
    /// User namespace — isolates UID/GID number spaces.
    User = 5,
    /// Cgroup namespace — isolates cgroup root directory view.
    Cgroup = 6,
    /// Time namespace — isolates CLOCK_MONOTONIC and CLOCK_BOOTTIME.
    Time = 7,
}

impl NamespaceType {
    /// Convert a `u8` index to a `NamespaceType`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the index is out of range.
    pub const fn from_index(idx: u8) -> Result<Self> {
        match idx {
            0 => Ok(Self::Mount),
            1 => Ok(Self::Pid),
            2 => Ok(Self::Net),
            3 => Ok(Self::Ipc),
            4 => Ok(Self::Uts),
            5 => Ok(Self::User),
            6 => Ok(Self::Cgroup),
            7 => Ok(Self::Time),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Return the index of this namespace type.
    pub const fn index(self) -> usize {
        self as usize
    }
}

// ── Namespace base struct ─────────────────────────────────────────

/// Base metadata for a namespace instance.
///
/// Every namespace, regardless of type, carries an identifier, its
/// type, a reference count, and an optional parent namespace ID
/// (for hierarchical namespaces like PID and user).
#[derive(Debug, Clone, Copy)]
pub struct Namespace {
    /// Unique namespace identifier.
    id: u64,
    /// The type of this namespace.
    ns_type: NamespaceType,
    /// Number of processes currently in this namespace.
    refcount: u32,
    /// Parent namespace ID, or 0 if this is the initial namespace.
    parent_id: u64,
}

impl Namespace {
    /// Create a new namespace with the given parameters.
    pub const fn new(id: u64, ns_type: NamespaceType, parent_id: u64) -> Self {
        Self {
            id,
            ns_type,
            refcount: 1,
            parent_id,
        }
    }

    /// Return the namespace identifier.
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Return the namespace type.
    pub const fn ns_type(&self) -> NamespaceType {
        self.ns_type
    }

    /// Return the current reference count.
    pub const fn refcount(&self) -> u32 {
        self.refcount
    }

    /// Return the parent namespace ID.
    pub const fn parent_id(&self) -> u64 {
        self.parent_id
    }

    /// Increment the reference count.
    fn acquire(&mut self) {
        self.refcount = self.refcount.saturating_add(1);
    }

    /// Decrement the reference count.
    ///
    /// Returns `true` if the count reached zero (namespace can be
    /// freed).
    fn release(&mut self) -> bool {
        self.refcount = self.refcount.saturating_sub(1);
        self.refcount == 0
    }
}

// ── PID translation entry ─────────────────────────────────────────

/// A single PID translation mapping.
///
/// Maps a virtual (namespace-local) PID to a global PID.
#[derive(Debug, Clone, Copy)]
struct PidMapping {
    /// Namespace-local (virtual) PID.
    ns_pid: u64,
    /// Global PID.
    global_pid: u64,
}

// ── PidNamespace ──────────────────────────────────────────────────

/// PID namespace providing isolated PID number spaces.
///
/// Each PID namespace maintains a translation table that maps
/// namespace-local PIDs to global PIDs. The init process (PID 1
/// within the namespace) is tracked separately.
#[derive(Debug)]
pub struct PidNamespace {
    /// Base namespace metadata.
    base: Namespace,
    /// PID translation table (namespace-local → global).
    mappings: [PidMapping; MAX_PID_MAPPINGS],
    /// Number of active mappings.
    count: usize,
    /// Global PID of the namespace init process (ns-local PID 1).
    init_pid: u64,
}

impl PidNamespace {
    /// Create a new PID namespace with the given ID and parent.
    ///
    /// The `init_pid` is the global PID of the process that will
    /// appear as PID 1 inside this namespace.
    pub const fn new(id: u64, parent_id: u64, init_pid: u64) -> Self {
        Self {
            base: Namespace::new(id, NamespaceType::Pid, parent_id),
            mappings: [PidMapping {
                ns_pid: 0,
                global_pid: 0,
            }; MAX_PID_MAPPINGS],
            count: 0,
            init_pid,
        }
    }

    /// Return the base namespace metadata.
    pub const fn base(&self) -> &Namespace {
        &self.base
    }

    /// Return the global PID of the init process in this namespace.
    pub const fn init_pid(&self) -> u64 {
        self.init_pid
    }

    /// Return the number of active PID mappings.
    pub const fn mapping_count(&self) -> usize {
        self.count
    }

    /// Add a PID mapping (namespace-local → global).
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the mapping table is full
    /// - `AlreadyExists` if `ns_pid` is already mapped
    pub fn add_mapping(&mut self, ns_pid: u64, global_pid: u64) -> Result<()> {
        let mut i = 0;
        while i < self.count {
            if self.mappings[i].ns_pid == ns_pid {
                return Err(Error::AlreadyExists);
            }
            i = i.saturating_add(1);
        }
        if self.count >= MAX_PID_MAPPINGS {
            return Err(Error::OutOfMemory);
        }
        self.mappings[self.count] = PidMapping { ns_pid, global_pid };
        self.count = self.count.saturating_add(1);
        Ok(())
    }

    /// Remove a PID mapping by namespace-local PID.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no mapping exists for this namespace PID
    pub fn remove_mapping(&mut self, ns_pid: u64) -> Result<()> {
        let mut i = 0;
        while i < self.count {
            if self.mappings[i].ns_pid == ns_pid {
                let last = self.count.saturating_sub(1);
                self.mappings[i] = self.mappings[last];
                self.mappings[last] = PidMapping {
                    ns_pid: 0,
                    global_pid: 0,
                };
                self.count = last;
                return Ok(());
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Translate a namespace-local PID to a global PID.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no mapping exists for this namespace PID
    pub fn translate_to_global(&self, ns_pid: u64) -> Result<u64> {
        let mut i = 0;
        while i < self.count {
            if self.mappings[i].ns_pid == ns_pid {
                return Ok(self.mappings[i].global_pid);
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Translate a global PID to a namespace-local PID.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no mapping exists for this global PID
    pub fn translate_to_ns(&self, global_pid: u64) -> Result<u64> {
        let mut i = 0;
        while i < self.count {
            if self.mappings[i].global_pid == global_pid {
                return Ok(self.mappings[i].ns_pid);
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }
}

// ── Mount entry ───────────────────────────────────────────────────

/// Maximum length of a mount point path (in bytes).
const MOUNT_PATH_LEN: usize = 128;

/// A single mount point entry within a mount namespace.
#[derive(Debug, Clone, Copy)]
struct MountEntry {
    /// Mount point path (null-terminated byte array).
    path: [u8; MOUNT_PATH_LEN],
    /// Length of the path (excluding null terminator).
    path_len: usize,
    /// Device identifier.
    device_id: u64,
    /// Mount flags (read-only, noexec, etc.).
    flags: u32,
    /// `true` if this entry is in use.
    active: bool,
}

impl MountEntry {
    /// An empty (inactive) mount entry.
    const EMPTY: Self = Self {
        path: [0u8; MOUNT_PATH_LEN],
        path_len: 0,
        device_id: 0,
        flags: 0,
        active: false,
    };
}

// ── MountNamespace ────────────────────────────────────────────────

/// Mount namespace providing an isolated set of filesystem mounts.
///
/// Each mount namespace has its own list of mount points and a
/// designated root mount. Processes in different mount namespaces
/// can see entirely different filesystem hierarchies.
#[derive(Debug)]
pub struct MountNamespace {
    /// Base namespace metadata.
    base: Namespace,
    /// Fixed-capacity mount point list.
    mounts: [MountEntry; MAX_MOUNTS],
    /// Number of active mounts.
    count: usize,
    /// Index of the root mount within `mounts`, if set.
    root_mount_idx: Option<usize>,
}

impl MountNamespace {
    /// Create a new empty mount namespace.
    pub const fn new(id: u64, parent_id: u64) -> Self {
        Self {
            base: Namespace::new(id, NamespaceType::Mount, parent_id),
            mounts: [MountEntry::EMPTY; MAX_MOUNTS],
            count: 0,
            root_mount_idx: None,
        }
    }

    /// Return the base namespace metadata.
    pub const fn base(&self) -> &Namespace {
        &self.base
    }

    /// Return the number of active mount points.
    pub const fn mount_count(&self) -> usize {
        self.count
    }

    /// Return the index of the root mount, if set.
    pub const fn root_mount_idx(&self) -> Option<usize> {
        self.root_mount_idx
    }

    /// Add a mount point.
    ///
    /// If `is_root` is `true`, this mount becomes the root mount
    /// for the namespace.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if the path is empty or too long
    /// - `OutOfMemory` if the mount table is full
    pub fn add_mount(
        &mut self,
        path: &[u8],
        device_id: u64,
        flags: u32,
        is_root: bool,
    ) -> Result<()> {
        if path.is_empty() || path.len() > MOUNT_PATH_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_MOUNTS {
            return Err(Error::OutOfMemory);
        }
        // Find a free slot.
        let mut slot = 0;
        while slot < MAX_MOUNTS {
            if !self.mounts[slot].active {
                let mut entry = MountEntry::EMPTY;
                entry.path[..path.len()].copy_from_slice(path);
                entry.path_len = path.len();
                entry.device_id = device_id;
                entry.flags = flags;
                entry.active = true;
                self.mounts[slot] = entry;
                self.count = self.count.saturating_add(1);
                if is_root {
                    self.root_mount_idx = Some(slot);
                }
                return Ok(());
            }
            slot = slot.saturating_add(1);
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a mount point by path.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no mount with this path exists
    pub fn remove_mount(&mut self, path: &[u8]) -> Result<()> {
        let mut i = 0;
        while i < MAX_MOUNTS {
            if self.mounts[i].active
                && self.mounts[i].path_len == path.len()
                && self.mounts[i].path[..path.len()] == *path
            {
                self.mounts[i] = MountEntry::EMPTY;
                self.count = self.count.saturating_sub(1);
                // Clear root index if this was the root.
                if self.root_mount_idx == Some(i) {
                    self.root_mount_idx = None;
                }
                return Ok(());
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }
}

// ── UtsNamespace ──────────────────────────────────────────────────

/// UTS namespace providing isolated hostname and domain name.
///
/// Mirrors the POSIX `utsname` fields `nodename` and `domainname`,
/// each stored as a null-terminated byte array of up to
/// [`UTS_NAME_LEN`] bytes (including the null terminator).
#[derive(Debug, Clone, Copy)]
pub struct UtsNamespace {
    /// Base namespace metadata.
    base: Namespace,
    /// Hostname (null-terminated, up to 65 bytes including NUL).
    nodename: [u8; UTS_NAME_LEN],
    /// Length of `nodename` (excluding null terminator).
    nodename_len: usize,
    /// NIS domain name (null-terminated, up to 65 bytes including NUL).
    domainname: [u8; UTS_NAME_LEN],
    /// Length of `domainname` (excluding null terminator).
    domainname_len: usize,
}

impl UtsNamespace {
    /// Create a new UTS namespace with empty names.
    pub const fn new(id: u64, parent_id: u64) -> Self {
        Self {
            base: Namespace::new(id, NamespaceType::Uts, parent_id),
            nodename: [0u8; UTS_NAME_LEN],
            nodename_len: 0,
            domainname: [0u8; UTS_NAME_LEN],
            domainname_len: 0,
        }
    }

    /// Return the base namespace metadata.
    pub const fn base(&self) -> &Namespace {
        &self.base
    }

    /// Return the hostname as a byte slice.
    pub fn nodename(&self) -> &[u8] {
        &self.nodename[..self.nodename_len]
    }

    /// Return the domain name as a byte slice.
    pub fn domainname(&self) -> &[u8] {
        &self.domainname[..self.domainname_len]
    }

    /// Set the hostname.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if the name exceeds capacity
    pub fn set_nodename(&mut self, name: &[u8]) -> Result<()> {
        if name.len() >= UTS_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        self.nodename = [0u8; UTS_NAME_LEN];
        self.nodename[..name.len()].copy_from_slice(name);
        self.nodename_len = name.len();
        Ok(())
    }

    /// Set the domain name.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if the name exceeds capacity
    pub fn set_domainname(&mut self, name: &[u8]) -> Result<()> {
        if name.len() >= UTS_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        self.domainname = [0u8; UTS_NAME_LEN];
        self.domainname[..name.len()].copy_from_slice(name);
        self.domainname_len = name.len();
        Ok(())
    }
}

// ── ID mapping entry ──────────────────────────────────────────────

/// A UID or GID mapping entry for a user namespace.
///
/// Maps a contiguous range of IDs from the namespace-local space
/// to the parent (or global) ID space.
#[derive(Debug, Clone, Copy)]
pub struct IdMapping {
    /// Start of the namespace-local ID range.
    ns_id: u32,
    /// Start of the host (parent namespace) ID range.
    host_id: u32,
    /// Number of IDs in this mapping range.
    count: u32,
}

impl IdMapping {
    /// An empty (zeroed) mapping entry.
    const EMPTY: Self = Self {
        ns_id: 0,
        host_id: 0,
        count: 0,
    };

    /// Create a new ID mapping entry.
    pub const fn new(ns_id: u32, host_id: u32, count: u32) -> Self {
        Self {
            ns_id,
            host_id,
            count,
        }
    }

    /// Return the namespace-local start ID.
    pub const fn ns_id(&self) -> u32 {
        self.ns_id
    }

    /// Return the host start ID.
    pub const fn host_id(&self) -> u32 {
        self.host_id
    }

    /// Return the number of IDs in this range.
    pub const fn count(&self) -> u32 {
        self.count
    }
}

// ── UserNamespace ─────────────────────────────────────────────────

/// User namespace providing isolated UID/GID number spaces.
///
/// Each user namespace has its own mapping tables that translate
/// between namespace-local UIDs/GIDs and parent (host) UIDs/GIDs.
/// The `owner` field identifies the effective UID (in the parent
/// namespace) of the process that created this namespace.
#[derive(Debug)]
pub struct UserNamespace {
    /// Base namespace metadata.
    base: Namespace,
    /// UID mapping table.
    uid_map: [IdMapping; MAX_ID_MAPPINGS],
    /// Number of active UID mappings.
    uid_count: usize,
    /// GID mapping table.
    gid_map: [IdMapping; MAX_ID_MAPPINGS],
    /// Number of active GID mappings.
    gid_count: usize,
    /// Effective UID of the creator (in the parent namespace).
    owner: u32,
}

impl UserNamespace {
    /// Create a new user namespace.
    ///
    /// The `owner` is the effective UID (in the parent namespace) of
    /// the creating process.
    pub const fn new(id: u64, parent_id: u64, owner: u32) -> Self {
        Self {
            base: Namespace::new(id, NamespaceType::User, parent_id),
            uid_map: [IdMapping::EMPTY; MAX_ID_MAPPINGS],
            uid_count: 0,
            gid_map: [IdMapping::EMPTY; MAX_ID_MAPPINGS],
            gid_count: 0,
            owner,
        }
    }

    /// Return the base namespace metadata.
    pub const fn base(&self) -> &Namespace {
        &self.base
    }

    /// Return the owner UID (in the parent namespace).
    pub const fn owner(&self) -> u32 {
        self.owner
    }

    /// Return the number of active UID mappings.
    pub const fn uid_mapping_count(&self) -> usize {
        self.uid_count
    }

    /// Return the number of active GID mappings.
    pub const fn gid_mapping_count(&self) -> usize {
        self.gid_count
    }

    /// Add a UID mapping.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the UID mapping table is full
    /// - `InvalidArgument` if `count` is zero
    pub fn add_uid_mapping(&mut self, mapping: IdMapping) -> Result<()> {
        if mapping.count == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.uid_count >= MAX_ID_MAPPINGS {
            return Err(Error::OutOfMemory);
        }
        self.uid_map[self.uid_count] = mapping;
        self.uid_count = self.uid_count.saturating_add(1);
        Ok(())
    }

    /// Add a GID mapping.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the GID mapping table is full
    /// - `InvalidArgument` if `count` is zero
    pub fn add_gid_mapping(&mut self, mapping: IdMapping) -> Result<()> {
        if mapping.count == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.gid_count >= MAX_ID_MAPPINGS {
            return Err(Error::OutOfMemory);
        }
        self.gid_map[self.gid_count] = mapping;
        self.gid_count = self.gid_count.saturating_add(1);
        Ok(())
    }

    /// Translate a namespace-local UID to a host UID.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the UID is not covered by any mapping
    pub fn translate_uid_to_host(&self, ns_uid: u32) -> Result<u32> {
        let mut i = 0;
        while i < self.uid_count {
            let m = &self.uid_map[i];
            if ns_uid >= m.ns_id && ns_uid < m.ns_id.saturating_add(m.count) {
                let offset = ns_uid.saturating_sub(m.ns_id);
                return Ok(m.host_id.saturating_add(offset));
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Translate a host UID to a namespace-local UID.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the UID is not covered by any mapping
    pub fn translate_uid_to_ns(&self, host_uid: u32) -> Result<u32> {
        let mut i = 0;
        while i < self.uid_count {
            let m = &self.uid_map[i];
            if host_uid >= m.host_id && host_uid < m.host_id.saturating_add(m.count) {
                let offset = host_uid.saturating_sub(m.host_id);
                return Ok(m.ns_id.saturating_add(offset));
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Translate a namespace-local GID to a host GID.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the GID is not covered by any mapping
    pub fn translate_gid_to_host(&self, ns_gid: u32) -> Result<u32> {
        let mut i = 0;
        while i < self.gid_count {
            let m = &self.gid_map[i];
            if ns_gid >= m.ns_id && ns_gid < m.ns_id.saturating_add(m.count) {
                let offset = ns_gid.saturating_sub(m.ns_id);
                return Ok(m.host_id.saturating_add(offset));
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Translate a host GID to a namespace-local GID.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the GID is not covered by any mapping
    pub fn translate_gid_to_ns(&self, host_gid: u32) -> Result<u32> {
        let mut i = 0;
        while i < self.gid_count {
            let m = &self.gid_map[i];
            if host_gid >= m.host_id && host_gid < m.host_id.saturating_add(m.count) {
                let offset = host_gid.saturating_sub(m.host_id);
                return Ok(m.ns_id.saturating_add(offset));
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }
}

// ── NamespaceSet ──────────────────────────────────────────────────

/// A process's namespace membership (one namespace ID per type).
///
/// Every process holds a `NamespaceSet` that records which namespace
/// it belongs to for each namespace type. A value of `0` means the
/// process is in the initial (root) namespace for that type.
#[derive(Debug, Clone, Copy)]
pub struct NamespaceSet {
    /// Namespace ID for each type, indexed by [`NamespaceType`].
    ns_ids: [u64; NS_TYPE_COUNT],
}

impl Default for NamespaceSet {
    fn default() -> Self {
        Self::new()
    }
}

impl NamespaceSet {
    /// Create a namespace set with all types set to the initial
    /// namespace (ID 0).
    pub const fn new() -> Self {
        Self {
            ns_ids: [0u64; NS_TYPE_COUNT],
        }
    }

    /// Get the namespace ID for the given type.
    pub const fn get(&self, ns_type: NamespaceType) -> u64 {
        self.ns_ids[ns_type.index()]
    }

    /// Set the namespace ID for the given type.
    pub fn set(&mut self, ns_type: NamespaceType, ns_id: u64) {
        self.ns_ids[ns_type.index()] = ns_id;
    }
}

// ── NamespaceRegistry ─────────────────────────────────────────────

/// Global registry of all namespace instances in the system.
///
/// Manages creation, lookup, reference counting, and destruction
/// of namespaces. The registry holds up to [`MAX_NAMESPACES`]
/// concurrent namespaces.
pub struct NamespaceRegistry {
    /// Storage for namespace metadata.
    namespaces: [Option<Namespace>; MAX_NAMESPACES],
    /// Number of active namespaces.
    count: usize,
    /// Monotonically increasing ID counter for new namespaces.
    next_id: u64,
}

impl Default for NamespaceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl NamespaceRegistry {
    /// Create an empty namespace registry.
    pub const fn new() -> Self {
        const NONE: Option<Namespace> = None;
        Self {
            namespaces: [NONE; MAX_NAMESPACES],
            count: 0,
            next_id: 1,
        }
    }

    /// Return the number of active namespaces.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if the registry contains no namespaces.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Allocate the next unique namespace ID.
    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        id
    }

    /// Create a new namespace of the given type.
    ///
    /// Returns the newly assigned namespace ID.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the registry is full
    pub fn create(&mut self, ns_type: NamespaceType, parent_id: u64) -> Result<u64> {
        if self.count >= MAX_NAMESPACES {
            return Err(Error::OutOfMemory);
        }
        let id = self.alloc_id();
        let ns = Namespace::new(id, ns_type, parent_id);
        // Find a free slot.
        let mut slot = 0;
        while slot < MAX_NAMESPACES {
            if self.namespaces[slot].is_none() {
                self.namespaces[slot] = Some(ns);
                self.count = self.count.saturating_add(1);
                return Ok(id);
            }
            slot = slot.saturating_add(1);
        }
        Err(Error::OutOfMemory)
    }

    /// Look up a namespace by its ID.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no namespace with this ID exists
    pub fn lookup(&self, ns_id: u64) -> Result<&Namespace> {
        let mut i = 0;
        while i < MAX_NAMESPACES {
            if let Some(ref ns) = self.namespaces[i] {
                if ns.id == ns_id {
                    return Ok(ns);
                }
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Look up a namespace by its ID (mutable).
    ///
    /// # Errors
    ///
    /// - `NotFound` if no namespace with this ID exists
    fn lookup_mut(&mut self, ns_id: u64) -> Result<&mut Namespace> {
        let idx = self
            .namespaces
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|ns| ns.id == ns_id))
            .ok_or(Error::NotFound)?;
        self.namespaces[idx].as_mut().ok_or(Error::NotFound)
    }

    /// Increment the reference count of a namespace.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no namespace with this ID exists
    pub fn acquire(&mut self, ns_id: u64) -> Result<()> {
        self.lookup_mut(ns_id)?.acquire();
        Ok(())
    }

    /// Decrement the reference count of a namespace.
    ///
    /// If the reference count reaches zero, the namespace is removed
    /// from the registry.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no namespace with this ID exists
    pub fn release(&mut self, ns_id: u64) -> Result<()> {
        let mut i = 0;
        while i < MAX_NAMESPACES {
            if let Some(ref mut ns) = self.namespaces[i] {
                if ns.id == ns_id {
                    if ns.release() {
                        self.namespaces[i] = None;
                        self.count = self.count.saturating_sub(1);
                    }
                    return Ok(());
                }
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Destroy a namespace by ID, regardless of reference count.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no namespace with this ID exists
    pub fn destroy(&mut self, ns_id: u64) -> Result<()> {
        let mut i = 0;
        while i < MAX_NAMESPACES {
            if let Some(ref ns) = self.namespaces[i] {
                if ns.id == ns_id {
                    self.namespaces[i] = None;
                    self.count = self.count.saturating_sub(1);
                    return Ok(());
                }
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }
}

// ── unshare / setns operations ────────────────────────────────────

/// Create new namespaces for the calling process.
///
/// For each flag set in `flags`, a new namespace of the
/// corresponding type is created in `registry` and the caller's
/// `ns_set` is updated to reference it. The new namespaces are
/// children of the caller's current namespaces.
///
/// # Errors
///
/// - `OutOfMemory` if the registry cannot accommodate new namespaces
pub fn unshare(
    flags: NsFlags,
    ns_set: &mut NamespaceSet,
    registry: &mut NamespaceRegistry,
) -> Result<()> {
    /// All namespace types in order for iteration.
    const ALL_TYPES: [NamespaceType; NS_TYPE_COUNT] = [
        NamespaceType::Mount,
        NamespaceType::Pid,
        NamespaceType::Net,
        NamespaceType::Ipc,
        NamespaceType::Uts,
        NamespaceType::User,
        NamespaceType::Cgroup,
        NamespaceType::Time,
    ];

    let mut i = 0;
    while i < NS_TYPE_COUNT {
        let ns_type = ALL_TYPES[i];
        let flag = NsFlags::for_type(ns_type);
        if flags.contains(flag) {
            let parent_id = ns_set.get(ns_type);
            let new_id = registry.create(ns_type, parent_id)?;
            ns_set.set(ns_type, new_id);
        }
        i = i.saturating_add(1);
    }
    Ok(())
}

/// Join an existing namespace.
///
/// The calling process's namespace of the given type is switched
/// to the namespace identified by `ns_id`. The old namespace's
/// reference count is decremented and the new one's is incremented.
///
/// # Errors
///
/// - `NotFound` if `ns_id` does not exist in the registry
/// - `InvalidArgument` if the namespace's type does not match
///   `ns_type`
pub fn setns(
    ns_id: u64,
    ns_type: NamespaceType,
    ns_set: &mut NamespaceSet,
    registry: &mut NamespaceRegistry,
) -> Result<()> {
    // Validate the target namespace exists and has the right type.
    let target = registry.lookup(ns_id)?;
    if target.ns_type() != ns_type {
        return Err(Error::InvalidArgument);
    }

    // Release old namespace reference.
    let old_id = ns_set.get(ns_type);
    if old_id != 0 {
        // Ignore error if old namespace was already removed.
        let _ = registry.release(old_id);
    }

    // Acquire new namespace reference and update the set.
    registry.acquire(ns_id)?;
    ns_set.set(ns_type, ns_id);
    Ok(())
}
