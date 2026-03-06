// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Process credentials management.
//!
//! Manages per-task security credentials: real/effective/saved UID and GID,
//! supplementary group lists, and POSIX capability sets. Supports
//! `setuid`/`setgid` transitions with proper privilege checks.
//!
//! # Architecture
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────┐
//! │                     CredentialStore                           │
//! │                                                               │
//! │  [TaskCredentials; MAX_TASKS]   per-task credential table     │
//! │  ┌─────────────────────────────────────────────────────────┐  │
//! │  │  UidGid  — real / effective / saved / fs uid + gid      │  │
//! │  │  GroupList — supplementary group membership              │  │
//! │  │  CapabilitySet — permitted / effective / inheritable     │  │
//! │  │  CredState — lifecycle state machine                     │  │
//! │  └─────────────────────────────────────────────────────────┘  │
//! │                                                               │
//! │  CredentialStats — global counters                            │
//! └───────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Security Model
//!
//! Credential transitions follow POSIX.1-2024 rules:
//! - Unprivileged processes may only set effective UID to real or saved UID.
//! - Root (UID 0) may set any UID.
//! - `setuid` binary execution replaces the effective UID and updates the
//!   saved set-user-ID.
//!
//! # Reference
//!
//! POSIX.1-2024 §4.13 (Privilege), §sys/types.h (uid_t, gid_t),
//! Linux `kernel/cred.c`, `include/linux/cred.h`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum tasks tracked in the credential store.
const MAX_TASKS: usize = 256;

/// Maximum supplementary groups per task.
const MAX_SUPPLEMENTARY_GROUPS: usize = 32;

/// Maximum number of capability bits.
const MAX_CAPS: usize = 64;

/// Root UID.
const ROOT_UID: u32 = 0;

/// Root GID.
const ROOT_GID: u32 = 0;

/// Capability bit: override file permission checks.
pub const CAP_DAC_OVERRIDE: u32 = 0;

/// Capability bit: change ownership of files.
pub const CAP_CHOWN: u32 = 1;

/// Capability bit: bypass permission checks on kill/signal.
pub const CAP_KILL: u32 = 2;

/// Capability bit: set UID arbitrarily.
pub const CAP_SETUID: u32 = 3;

/// Capability bit: set GID arbitrarily.
pub const CAP_SETGID: u32 = 4;

/// Capability bit: perform network operations.
pub const CAP_NET_ADMIN: u32 = 5;

/// Capability bit: bind to privileged ports.
pub const CAP_NET_BIND_SERVICE: u32 = 6;

/// Capability bit: general system administration.
pub const CAP_SYS_ADMIN: u32 = 7;

/// Capability bit: load and unload kernel modules.
pub const CAP_SYS_MODULE: u32 = 8;

/// Capability bit: reboot the system.
pub const CAP_SYS_BOOT: u32 = 9;

/// Capability bit: override resource limits.
pub const CAP_SYS_RESOURCE: u32 = 10;

/// Capability bit: perform raw I/O operations.
pub const CAP_SYS_RAWIO: u32 = 11;

// ── CredState ────────────────────────────────────────────────────────────────

/// Lifecycle state of a task's credential set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredState {
    /// Slot is free and available for allocation.
    Free,
    /// Credentials are active and in use.
    Active,
    /// Credentials are being modified (transition in progress).
    Transitioning,
    /// Credentials have been frozen (immutable after exec).
    Frozen,
}

impl Default for CredState {
    fn default() -> Self {
        Self::Free
    }
}

// ── UidGid ───────────────────────────────────────────────────────────────────

/// Complete UID/GID quadruple for a task.
///
/// POSIX defines four UID values per process:
/// - **real** — the user who started the process
/// - **effective** — used for permission checks
/// - **saved** — preserved across `exec` for privilege restoration
/// - **fs** — used for filesystem access (Linux extension)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UidGid {
    /// Real user ID.
    pub ruid: u32,
    /// Effective user ID.
    pub euid: u32,
    /// Saved set-user-ID.
    pub suid: u32,
    /// Filesystem user ID.
    pub fsuid: u32,
    /// Real group ID.
    pub rgid: u32,
    /// Effective group ID.
    pub egid: u32,
    /// Saved set-group-ID.
    pub sgid: u32,
    /// Filesystem group ID.
    pub fsgid: u32,
}

impl Default for UidGid {
    fn default() -> Self {
        Self {
            ruid: ROOT_UID,
            euid: ROOT_UID,
            suid: ROOT_UID,
            fsuid: ROOT_UID,
            rgid: ROOT_GID,
            egid: ROOT_GID,
            sgid: ROOT_GID,
            fsgid: ROOT_GID,
        }
    }
}

impl UidGid {
    /// Create a root credential set.
    pub const fn root() -> Self {
        Self {
            ruid: ROOT_UID,
            euid: ROOT_UID,
            suid: ROOT_UID,
            fsuid: ROOT_UID,
            rgid: ROOT_GID,
            egid: ROOT_GID,
            sgid: ROOT_GID,
            fsgid: ROOT_GID,
        }
    }

    /// Create credentials for a regular user.
    pub const fn new(uid: u32, gid: u32) -> Self {
        Self {
            ruid: uid,
            euid: uid,
            suid: uid,
            fsuid: uid,
            rgid: gid,
            egid: gid,
            sgid: gid,
            fsgid: gid,
        }
    }

    /// Return `true` if the effective UID is root.
    pub fn is_privileged(&self) -> bool {
        self.euid == ROOT_UID
    }
}

// ── CapabilitySet ────────────────────────────────────────────────────────────

/// POSIX capability bitmask for a task.
///
/// Each bit corresponds to a specific privilege (see `CAP_*` constants).
/// Three independent sets determine what the task can do:
/// - **permitted** — upper bound on capabilities the task may assume
/// - **effective** — currently active capabilities for permission checks
/// - **inheritable** — capabilities preserved across `execve`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilitySet {
    /// Permitted capabilities (upper bound).
    pub permitted: u64,
    /// Effective capabilities (active).
    pub effective: u64,
    /// Inheritable capabilities (preserved across exec).
    pub inheritable: u64,
}

impl Default for CapabilitySet {
    fn default() -> Self {
        Self {
            permitted: 0,
            effective: 0,
            inheritable: 0,
        }
    }
}

impl CapabilitySet {
    /// Full capability set (all bits set).
    pub const fn full() -> Self {
        Self {
            permitted: u64::MAX,
            effective: u64::MAX,
            inheritable: u64::MAX,
        }
    }

    /// Empty capability set (no privileges).
    pub const fn empty() -> Self {
        Self {
            permitted: 0,
            effective: 0,
            inheritable: 0,
        }
    }

    /// Check whether a specific capability is in the effective set.
    pub fn has_effective(&self, cap: u32) -> bool {
        if cap as usize >= MAX_CAPS {
            return false;
        }
        (self.effective & (1u64 << cap)) != 0
    }

    /// Check whether a specific capability is in the permitted set.
    pub fn has_permitted(&self, cap: u32) -> bool {
        if cap as usize >= MAX_CAPS {
            return false;
        }
        (self.permitted & (1u64 << cap)) != 0
    }

    /// Raise a capability in the effective set if it is permitted.
    ///
    /// # Errors
    ///
    /// - [`Error::PermissionDenied`] if the capability is not in
    ///   the permitted set.
    /// - [`Error::InvalidArgument`] if `cap` is out of range.
    pub fn raise_effective(&mut self, cap: u32) -> Result<()> {
        if cap as usize >= MAX_CAPS {
            return Err(Error::InvalidArgument);
        }
        let mask = 1u64 << cap;
        if (self.permitted & mask) == 0 {
            return Err(Error::PermissionDenied);
        }
        self.effective |= mask;
        Ok(())
    }

    /// Drop a capability from the effective set.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `cap` is out of range.
    pub fn drop_effective(&mut self, cap: u32) -> Result<()> {
        if cap as usize >= MAX_CAPS {
            return Err(Error::InvalidArgument);
        }
        self.effective &= !(1u64 << cap);
        Ok(())
    }

    /// Drop a capability from all three sets permanently.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `cap` is out of range.
    pub fn drop_all(&mut self, cap: u32) -> Result<()> {
        if cap as usize >= MAX_CAPS {
            return Err(Error::InvalidArgument);
        }
        let mask = !(1u64 << cap);
        self.permitted &= mask;
        self.effective &= mask;
        self.inheritable &= mask;
        Ok(())
    }

    /// Compute the capability set after `execve`.
    ///
    /// new_permitted  = (old_inheritable & file_inheritable)
    ///                | file_permitted
    /// new_effective  = new_permitted   (if file has set-effective bit)
    /// new_inheritable = old_inheritable
    pub fn apply_exec(
        &self,
        file_permitted: u64,
        file_inheritable: u64,
        file_effective_bit: bool,
    ) -> Self {
        let new_permitted = (self.inheritable & file_inheritable) | file_permitted;
        let new_effective = if file_effective_bit { new_permitted } else { 0 };
        Self {
            permitted: new_permitted,
            effective: new_effective,
            inheritable: self.inheritable,
        }
    }
}

// ── GroupList ─────────────────────────────────────────────────────────────────

/// Supplementary group list for a task.
///
/// A task may belong to up to [`MAX_SUPPLEMENTARY_GROUPS`] additional
/// groups beyond its primary GID.
#[derive(Debug, Clone, Copy)]
pub struct GroupList {
    /// Group IDs.
    groups: [u32; MAX_SUPPLEMENTARY_GROUPS],
    /// Number of valid entries.
    count: usize,
}

impl Default for GroupList {
    fn default() -> Self {
        Self {
            groups: [0u32; MAX_SUPPLEMENTARY_GROUPS],
            count: 0,
        }
    }
}

impl GroupList {
    /// Create an empty group list.
    pub const fn new() -> Self {
        Self {
            groups: [0u32; MAX_SUPPLEMENTARY_GROUPS],
            count: 0,
        }
    }

    /// Add a group to the list.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the list is full.
    /// - [`Error::AlreadyExists`] if the group is already present.
    pub fn add(&mut self, gid: u32) -> Result<()> {
        if self.contains(gid) {
            return Err(Error::AlreadyExists);
        }
        if self.count >= MAX_SUPPLEMENTARY_GROUPS {
            return Err(Error::OutOfMemory);
        }
        self.groups[self.count] = gid;
        self.count += 1;
        Ok(())
    }

    /// Remove a group from the list.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the group is not present.
    pub fn remove(&mut self, gid: u32) -> Result<()> {
        let pos = self.groups[..self.count].iter().position(|&g| g == gid);
        match pos {
            Some(idx) => {
                self.groups[idx] = self.groups[self.count - 1];
                self.count -= 1;
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Check whether a group is in the list.
    pub fn contains(&self, gid: u32) -> bool {
        self.groups[..self.count].contains(&gid)
    }

    /// Return the supplementary groups as a slice.
    pub fn as_slice(&self) -> &[u32] {
        &self.groups[..self.count]
    }

    /// Return the number of supplementary groups.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if there are no supplementary groups.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Replace the entire group list from a slice.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the slice is too long.
    pub fn set_groups(&mut self, gids: &[u32]) -> Result<()> {
        if gids.len() > MAX_SUPPLEMENTARY_GROUPS {
            return Err(Error::InvalidArgument);
        }
        self.groups[..gids.len()].copy_from_slice(gids);
        self.count = gids.len();
        Ok(())
    }
}

// ── TaskCredentials ──────────────────────────────────────────────────────────

/// Complete credential set for a single task.
///
/// Aggregates UID/GID, supplementary groups, capability sets, and
/// lifecycle state into a single structure that the scheduler and
/// permission checks can consult.
#[derive(Debug, Clone, Copy)]
pub struct TaskCredentials {
    /// Task identifier.
    pub task_id: u64,
    /// UID/GID quadruple.
    pub ids: UidGid,
    /// Supplementary group list.
    pub groups: GroupList,
    /// Capability sets.
    pub caps: CapabilitySet,
    /// Credential lifecycle state.
    pub state: CredState,
    /// Whether the no-new-privs flag is set.
    pub no_new_privs: bool,
    /// Whether the task has the dumpable attribute.
    pub dumpable: bool,
    /// Securebits flags (POSIX.1e).
    pub securebits: u32,
}

impl Default for TaskCredentials {
    fn default() -> Self {
        Self {
            task_id: 0,
            ids: UidGid::default(),
            groups: GroupList::new(),
            caps: CapabilitySet::empty(),
            state: CredState::Free,
            no_new_privs: false,
            dumpable: true,
            securebits: 0,
        }
    }
}

impl TaskCredentials {
    /// Create root credentials for the given task.
    pub fn new_root(task_id: u64) -> Self {
        Self {
            task_id,
            ids: UidGid::root(),
            groups: GroupList::new(),
            caps: CapabilitySet::full(),
            state: CredState::Active,
            no_new_privs: false,
            dumpable: true,
            securebits: 0,
        }
    }

    /// Create unprivileged credentials for the given task.
    pub fn new_user(task_id: u64, uid: u32, gid: u32) -> Self {
        Self {
            task_id,
            ids: UidGid::new(uid, gid),
            groups: GroupList::new(),
            caps: CapabilitySet::empty(),
            state: CredState::Active,
            no_new_privs: false,
            dumpable: true,
            securebits: 0,
        }
    }

    /// Return `true` if the effective UID is root or the
    /// specified capability is in the effective set.
    pub fn capable(&self, cap: u32) -> bool {
        self.ids.is_privileged() || self.caps.has_effective(cap)
    }
}

// ── CredentialStats ──────────────────────────────────────────────────────────

/// Global statistics for the credential subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct CredentialStats {
    /// Number of active credential entries.
    pub active_count: u64,
    /// Total setuid transitions performed.
    pub setuid_count: u64,
    /// Total setgid transitions performed.
    pub setgid_count: u64,
    /// Total credential allocations.
    pub alloc_count: u64,
    /// Total credential deallocations.
    pub free_count: u64,
    /// Total capability drops.
    pub cap_drop_count: u64,
    /// Failed privilege escalation attempts.
    pub denied_count: u64,
}

// ── CredentialStore ──────────────────────────────────────────────────────────

/// System-wide credential store.
///
/// Maintains a fixed-size table of per-task credentials and provides
/// APIs for credential lookup, modification, and lifecycle management.
pub struct CredentialStore {
    /// Per-task credential table.
    tasks: [TaskCredentials; MAX_TASKS],
    /// Number of active credential entries.
    active_count: usize,
    /// Global statistics.
    stats: CredentialStats,
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialStore {
    /// Create a new, empty credential store.
    pub const fn new() -> Self {
        const EMPTY: TaskCredentials = TaskCredentials {
            task_id: 0,
            ids: UidGid {
                ruid: 0,
                euid: 0,
                suid: 0,
                fsuid: 0,
                rgid: 0,
                egid: 0,
                sgid: 0,
                fsgid: 0,
            },
            groups: GroupList {
                groups: [0u32; MAX_SUPPLEMENTARY_GROUPS],
                count: 0,
            },
            caps: CapabilitySet {
                permitted: 0,
                effective: 0,
                inheritable: 0,
            },
            state: CredState::Free,
            no_new_privs: false,
            dumpable: true,
            securebits: 0,
        };
        Self {
            tasks: [EMPTY; MAX_TASKS],
            active_count: 0,
            stats: CredentialStats {
                active_count: 0,
                setuid_count: 0,
                setgid_count: 0,
                alloc_count: 0,
                free_count: 0,
                cap_drop_count: 0,
                denied_count: 0,
            },
        }
    }

    /// Allocate a root credential entry for `task_id`.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the table is full.
    /// - [`Error::AlreadyExists`] if the task already has credentials.
    pub fn alloc_root(&mut self, task_id: u64) -> Result<()> {
        if self.find_index(task_id).is_some() {
            return Err(Error::AlreadyExists);
        }
        let idx = self.find_free_slot()?;
        self.tasks[idx] = TaskCredentials::new_root(task_id);
        self.active_count += 1;
        self.stats.alloc_count += 1;
        self.stats.active_count = self.active_count as u64;
        Ok(())
    }

    /// Allocate an unprivileged credential entry for `task_id`.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the table is full.
    /// - [`Error::AlreadyExists`] if the task already has credentials.
    pub fn alloc_user(&mut self, task_id: u64, uid: u32, gid: u32) -> Result<()> {
        if self.find_index(task_id).is_some() {
            return Err(Error::AlreadyExists);
        }
        let idx = self.find_free_slot()?;
        self.tasks[idx] = TaskCredentials::new_user(task_id, uid, gid);
        self.active_count += 1;
        self.stats.alloc_count += 1;
        self.stats.active_count = self.active_count as u64;
        Ok(())
    }

    /// Free the credential entry for `task_id`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the task has no credentials.
    pub fn free(&mut self, task_id: u64) -> Result<()> {
        let idx = self.find_index(task_id).ok_or(Error::NotFound)?;
        self.tasks[idx] = TaskCredentials::default();
        self.active_count -= 1;
        self.stats.free_count += 1;
        self.stats.active_count = self.active_count as u64;
        Ok(())
    }

    /// Look up credentials for `task_id`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the task has no credentials.
    pub fn get(&self, task_id: u64) -> Result<&TaskCredentials> {
        let idx = self.find_index(task_id).ok_or(Error::NotFound)?;
        Ok(&self.tasks[idx])
    }

    /// Look up mutable credentials for `task_id`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the task has no credentials.
    pub fn get_mut(&mut self, task_id: u64) -> Result<&mut TaskCredentials> {
        let idx = self.find_index(task_id).ok_or(Error::NotFound)?;
        Ok(&mut self.tasks[idx])
    }

    /// Perform a `setuid` transition for `task_id`.
    ///
    /// POSIX rules:
    /// - If the caller has `CAP_SETUID` or is root, any UID is allowed
    ///   and real/effective/saved are all set.
    /// - Otherwise, `new_uid` must equal the current real or saved UID,
    ///   and only the effective UID is changed.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the task has no credentials.
    /// - [`Error::PermissionDenied`] if the transition is not allowed.
    pub fn setuid(&mut self, task_id: u64, new_uid: u32) -> Result<()> {
        let idx = self.find_index(task_id).ok_or(Error::NotFound)?;
        let cred = &mut self.tasks[idx];

        if cred.state == CredState::Frozen {
            self.stats.denied_count += 1;
            return Err(Error::PermissionDenied);
        }

        let privileged = cred.capable(CAP_SETUID);

        if privileged {
            cred.ids.ruid = new_uid;
            cred.ids.euid = new_uid;
            cred.ids.suid = new_uid;
            cred.ids.fsuid = new_uid;
        } else if new_uid == cred.ids.ruid || new_uid == cred.ids.suid {
            cred.ids.euid = new_uid;
            cred.ids.fsuid = new_uid;
        } else {
            self.stats.denied_count += 1;
            return Err(Error::PermissionDenied);
        }

        self.stats.setuid_count += 1;
        Ok(())
    }

    /// Perform a `setgid` transition for `task_id`.
    ///
    /// Rules mirror `setuid` but operate on group IDs and require
    /// `CAP_SETGID` for arbitrary transitions.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the task has no credentials.
    /// - [`Error::PermissionDenied`] if the transition is not allowed.
    pub fn setgid(&mut self, task_id: u64, new_gid: u32) -> Result<()> {
        let idx = self.find_index(task_id).ok_or(Error::NotFound)?;
        let cred = &mut self.tasks[idx];

        if cred.state == CredState::Frozen {
            self.stats.denied_count += 1;
            return Err(Error::PermissionDenied);
        }

        let privileged = cred.capable(CAP_SETGID);

        if privileged {
            cred.ids.rgid = new_gid;
            cred.ids.egid = new_gid;
            cred.ids.sgid = new_gid;
            cred.ids.fsgid = new_gid;
        } else if new_gid == cred.ids.rgid || new_gid == cred.ids.sgid {
            cred.ids.egid = new_gid;
            cred.ids.fsgid = new_gid;
        } else {
            self.stats.denied_count += 1;
            return Err(Error::PermissionDenied);
        }

        self.stats.setgid_count += 1;
        Ok(())
    }

    /// Perform a `setresuid` transition (set real, effective, saved).
    ///
    /// A value of `u32::MAX` means "don't change". Unprivileged callers
    /// may only set each field to the current real, effective, or saved
    /// UID.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the task has no credentials.
    /// - [`Error::PermissionDenied`] if the transition is not allowed.
    pub fn setresuid(&mut self, task_id: u64, ruid: u32, euid: u32, suid: u32) -> Result<()> {
        let idx = self.find_index(task_id).ok_or(Error::NotFound)?;
        let cred = &mut self.tasks[idx];

        if cred.state == CredState::Frozen {
            self.stats.denied_count += 1;
            return Err(Error::PermissionDenied);
        }

        let privileged = cred.capable(CAP_SETUID);
        let cur_r = cred.ids.ruid;
        let cur_e = cred.ids.euid;
        let cur_s = cred.ids.suid;

        let allowed = |val: u32| -> bool {
            val == u32::MAX || privileged || val == cur_r || val == cur_e || val == cur_s
        };

        if !allowed(ruid) || !allowed(euid) || !allowed(suid) {
            self.stats.denied_count += 1;
            return Err(Error::PermissionDenied);
        }

        if ruid != u32::MAX {
            cred.ids.ruid = ruid;
        }
        if euid != u32::MAX {
            cred.ids.euid = euid;
            cred.ids.fsuid = euid;
        }
        if suid != u32::MAX {
            cred.ids.suid = suid;
        }

        self.stats.setuid_count += 1;
        Ok(())
    }

    /// Apply setuid-binary credential transformation during `execve`.
    ///
    /// If the binary has the set-user-ID bit:
    /// - effective UID becomes the file owner UID.
    /// - saved UID becomes the file owner UID.
    ///
    /// If `no_new_privs` is set, the transformation is denied.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the task has no credentials.
    /// - [`Error::PermissionDenied`] if `no_new_privs` is set.
    pub fn apply_setuid_exec(&mut self, task_id: u64, file_uid: u32) -> Result<()> {
        let idx = self.find_index(task_id).ok_or(Error::NotFound)?;
        let cred = &mut self.tasks[idx];

        if cred.no_new_privs {
            self.stats.denied_count += 1;
            return Err(Error::PermissionDenied);
        }

        cred.ids.euid = file_uid;
        cred.ids.suid = file_uid;
        cred.ids.fsuid = file_uid;
        self.stats.setuid_count += 1;
        Ok(())
    }

    /// Apply setgid-binary credential transformation during `execve`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the task has no credentials.
    /// - [`Error::PermissionDenied`] if `no_new_privs` is set.
    pub fn apply_setgid_exec(&mut self, task_id: u64, file_gid: u32) -> Result<()> {
        let idx = self.find_index(task_id).ok_or(Error::NotFound)?;
        let cred = &mut self.tasks[idx];

        if cred.no_new_privs {
            self.stats.denied_count += 1;
            return Err(Error::PermissionDenied);
        }

        cred.ids.egid = file_gid;
        cred.ids.sgid = file_gid;
        cred.ids.fsgid = file_gid;
        self.stats.setgid_count += 1;
        Ok(())
    }

    /// Freeze credentials for `task_id` (make immutable).
    ///
    /// Once frozen, no further UID/GID transitions are permitted.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the task has no credentials.
    pub fn freeze(&mut self, task_id: u64) -> Result<()> {
        let cred = self.get_mut(task_id)?;
        cred.state = CredState::Frozen;
        Ok(())
    }

    /// Set the `no_new_privs` flag for `task_id`.
    ///
    /// Once set, this flag cannot be unset and prevents any future
    /// privilege escalation via setuid/setgid binaries or capability
    /// gain through `execve`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the task has no credentials.
    pub fn set_no_new_privs(&mut self, task_id: u64) -> Result<()> {
        let cred = self.get_mut(task_id)?;
        cred.no_new_privs = true;
        Ok(())
    }

    /// Check if `task_id` has the specified capability.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the task has no credentials.
    pub fn has_capability(&self, task_id: u64, cap: u32) -> Result<bool> {
        let cred = self.get(task_id)?;
        Ok(cred.capable(cap))
    }

    /// Drop a capability from all sets for `task_id`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the task has no credentials.
    /// - [`Error::InvalidArgument`] if `cap` is out of range.
    pub fn drop_capability(&mut self, task_id: u64, cap: u32) -> Result<()> {
        let cred = self.get_mut(task_id)?;
        cred.caps.drop_all(cap)?;
        self.stats.cap_drop_count += 1;
        Ok(())
    }

    /// Return a snapshot of the global credential statistics.
    pub fn stats(&self) -> &CredentialStats {
        &self.stats
    }

    /// Return the number of active credential entries.
    pub fn active_count(&self) -> usize {
        self.active_count
    }

    // ── Private helpers ──────────────────────────────────────────

    /// Find the table index for `task_id`.
    fn find_index(&self, task_id: u64) -> Option<usize> {
        self.tasks
            .iter()
            .position(|t| t.state != CredState::Free && t.task_id == task_id)
    }

    /// Find a free slot in the table.
    fn find_free_slot(&self) -> Result<usize> {
        self.tasks
            .iter()
            .position(|t| t.state == CredState::Free)
            .ok_or(Error::OutOfMemory)
    }
}
