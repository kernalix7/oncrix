// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Network class cgroup controller (`net_cls`).
//!
//! Assigns a traffic control class identifier (`classid`) to processes
//! within a cgroup. The classid is stamped on every packet originating
//! from those processes, allowing the `tc` (traffic control) subsystem
//! to classify and schedule traffic without per-packet deep inspection.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                   NetClsCgroupSubsystem                          │
//! │                                                                  │
//! │  [NetClsGroup; MAX_GROUPS]  — per-cgroup classification state    │
//! │  ┌────────────────────────────────────────────────────────────┐  │
//! │  │  NetClsGroup                                               │  │
//! │  │    cgroup_id: u64                                          │  │
//! │  │    classid: ClassId        — assigned tc class              │  │
//! │  │    pids: [u64; MAX_PIDS]   — attached processes             │  │
//! │  │    NetClsState — lifecycle                                  │  │
//! │  └────────────────────────────────────────────────────────────┘  │
//! │                                                                  │
//! │  NetClsCgroupStats — global counters                             │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # ClassId Encoding
//!
//! A classid is a 32-bit value split into `major:minor` (each 16 bits):
//! - `major` — identifies the qdisc (queueing discipline).
//! - `minor` — identifies the class within the qdisc.
//! - `0:0` (zero) means unclassified.
//!
//! # Reference
//!
//! Linux `net/core/netclassid_cgroup.c`,
//! `Documentation/admin-guide/cgroup-v1/net_cls.rst`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of net_cls cgroup groups.
const MAX_GROUPS: usize = 64;

/// Maximum PIDs per cgroup group.
const MAX_PIDS: usize = 64;

/// Maximum cgroup name length.
const MAX_NAME_LEN: usize = 64;

/// Default classid (unclassified).
const DEFAULT_CLASSID: u32 = 0;

// ── ClassId ─────────────────────────────────────────────────────────────────

/// Traffic control class identifier (major:minor, each 16 bits).
///
/// Stamps every packet from attached processes so `tc` can classify
/// them without deep-packet inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClassId(pub u32);

impl ClassId {
    /// The unclassified (pass-through) classid.
    pub const UNCLASSIFIED: Self = Self(0);

    /// Create a classid from separate major and minor parts.
    pub const fn from_parts(major: u16, minor: u16) -> Self {
        Self(((major as u32) << 16) | (minor as u32))
    }

    /// Return the major component (upper 16 bits).
    pub fn major(self) -> u16 {
        (self.0 >> 16) as u16
    }

    /// Return the minor component (lower 16 bits).
    pub fn minor(self) -> u16 {
        (self.0 & 0xFFFF) as u16
    }

    /// Return `true` if this represents the unclassified default.
    pub fn is_unclassified(self) -> bool {
        self.0 == 0
    }

    /// Return the raw 32-bit value.
    pub const fn raw(self) -> u32 {
        self.0
    }
}

impl core::fmt::Display for ClassId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:04x}:{:04x}", self.major(), self.minor())
    }
}

// ── NetClsState ─────────────────────────────────────────────────────────────

/// Lifecycle state of a net_cls cgroup group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetClsState {
    /// Slot is free.
    Free,
    /// Group is active.
    Active,
    /// Group is being torn down.
    Dying,
}

impl Default for NetClsState {
    fn default() -> Self {
        Self::Free
    }
}

// ── NetClsGroup ─────────────────────────────────────────────────────────────

/// A single net_cls cgroup group.
///
/// Associates a set of PIDs with a traffic control classid. The
/// classid is written to `net_cls.classid` in the cgroup filesystem.
#[derive(Debug, Clone, Copy)]
pub struct NetClsGroup {
    /// Unique cgroup identifier.
    pub cgroup_id: u64,
    /// Cgroup name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Traffic control classid.
    pub classid: ClassId,
    /// Attached process IDs.
    pids: [u64; MAX_PIDS],
    /// Number of attached PIDs.
    pid_count: usize,
    /// Lifecycle state.
    pub state: NetClsState,
    /// Packets classified (classid != 0).
    pub packets_classified: u64,
    /// Packets that passed through unclassified.
    pub packets_unclassified: u64,
    /// Parent cgroup ID (0 if root).
    pub parent_id: u64,
}

impl Default for NetClsGroup {
    fn default() -> Self {
        Self {
            cgroup_id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            classid: ClassId(DEFAULT_CLASSID),
            pids: [0u64; MAX_PIDS],
            pid_count: 0,
            state: NetClsState::Free,
            packets_classified: 0,
            packets_unclassified: 0,
            parent_id: 0,
        }
    }
}

impl NetClsGroup {
    /// Return the group name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Set the group name.
    fn set_name(&mut self, name: &[u8]) {
        let copy_len = name.len().min(MAX_NAME_LEN);
        self.name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.name_len = copy_len;
    }

    /// Set the classid for this group.
    pub fn set_classid(&mut self, classid: ClassId) {
        self.classid = classid;
    }

    /// Attach a PID to this group.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the PID table is full.
    /// - [`Error::AlreadyExists`] if the PID is already attached.
    pub fn attach_pid(&mut self, pid: u64) -> Result<()> {
        if self.pids[..self.pid_count].contains(&pid) {
            return Err(Error::AlreadyExists);
        }
        if self.pid_count >= MAX_PIDS {
            return Err(Error::OutOfMemory);
        }
        self.pids[self.pid_count] = pid;
        self.pid_count += 1;
        Ok(())
    }

    /// Detach a PID from this group.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the PID is not attached.
    pub fn detach_pid(&mut self, pid: u64) -> Result<()> {
        let pos = self.pids[..self.pid_count].iter().position(|&p| p == pid);
        match pos {
            Some(idx) => {
                self.pids[idx] = self.pids[self.pid_count - 1];
                self.pid_count -= 1;
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Check whether a PID is attached.
    pub fn has_pid(&self, pid: u64) -> bool {
        self.pids[..self.pid_count].contains(&pid)
    }

    /// Classify a packet from `pid`.
    ///
    /// Returns the classid if the PID is in this group, updating
    /// statistics. Returns `None` if the PID is not attached.
    pub fn classify(&mut self, pid: u64) -> Option<ClassId> {
        if !self.has_pid(pid) {
            return None;
        }
        if self.classid.is_unclassified() {
            self.packets_unclassified += 1;
        } else {
            self.packets_classified += 1;
        }
        Some(self.classid)
    }

    /// Return a slice of attached PIDs.
    pub fn pids(&self) -> &[u64] {
        &self.pids[..self.pid_count]
    }

    /// Return the number of attached PIDs.
    pub fn pid_count(&self) -> usize {
        self.pid_count
    }
}

// ── NetClsCgroupStats ───────────────────────────────────────────────────────

/// Global statistics for the net_cls cgroup controller.
#[derive(Debug, Clone, Copy, Default)]
pub struct NetClsCgroupStats {
    /// Number of active groups.
    pub active_groups: u64,
    /// Total groups created.
    pub groups_created: u64,
    /// Total groups destroyed.
    pub groups_destroyed: u64,
    /// Total PID attach operations.
    pub pid_attaches: u64,
    /// Total PID detach operations.
    pub pid_detaches: u64,
    /// Total classify lookups.
    pub classify_lookups: u64,
    /// Total packets classified (matched a non-zero classid).
    pub total_classified: u64,
}

// ── NetClsCgroupSubsystem ───────────────────────────────────────────────────

/// System-wide net_cls cgroup controller.
///
/// Manages cgroup groups that classify network packets by PID
/// membership. The subsystem provides a fast path for the networking
/// stack to look up the classid for a packet's originating PID.
pub struct NetClsCgroupSubsystem {
    /// Per-group records.
    groups: [NetClsGroup; MAX_GROUPS],
    /// Number of active groups.
    active_count: usize,
    /// Next group identifier.
    next_id: u64,
    /// Global statistics.
    stats: NetClsCgroupStats,
}

impl Default for NetClsCgroupSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl NetClsCgroupSubsystem {
    /// Create a new, empty net_cls cgroup subsystem.
    pub const fn new() -> Self {
        const EMPTY: NetClsGroup = NetClsGroup {
            cgroup_id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            classid: ClassId(DEFAULT_CLASSID),
            pids: [0u64; MAX_PIDS],
            pid_count: 0,
            state: NetClsState::Free,
            packets_classified: 0,
            packets_unclassified: 0,
            parent_id: 0,
        };
        Self {
            groups: [EMPTY; MAX_GROUPS],
            active_count: 0,
            next_id: 1,
            stats: NetClsCgroupStats {
                active_groups: 0,
                groups_created: 0,
                groups_destroyed: 0,
                pid_attaches: 0,
                pid_detaches: 0,
                classify_lookups: 0,
                total_classified: 0,
            },
        }
    }

    /// Create a new net_cls cgroup group.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the group table is full.
    pub fn create_group(&mut self, name: &[u8], parent_id: u64) -> Result<u64> {
        let slot = self
            .groups
            .iter()
            .position(|g| g.state == NetClsState::Free)
            .ok_or(Error::OutOfMemory)?;

        let gid = self.next_id;
        self.next_id += 1;

        self.groups[slot] = NetClsGroup::default();
        self.groups[slot].cgroup_id = gid;
        self.groups[slot].set_name(name);
        self.groups[slot].parent_id = parent_id;
        self.groups[slot].state = NetClsState::Active;

        self.active_count += 1;
        self.stats.active_groups = self.active_count as u64;
        self.stats.groups_created += 1;

        Ok(gid)
    }

    /// Destroy a net_cls cgroup group.
    ///
    /// All attached PIDs are detached.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the group does not exist.
    pub fn destroy_group(&mut self, cgroup_id: u64) -> Result<()> {
        let idx = self.find_index(cgroup_id).ok_or(Error::NotFound)?;
        self.groups[idx] = NetClsGroup::default();
        self.active_count -= 1;
        self.stats.active_groups = self.active_count as u64;
        self.stats.groups_destroyed += 1;
        Ok(())
    }

    /// Set the classid for a cgroup group.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the group does not exist.
    pub fn set_classid(&mut self, cgroup_id: u64, classid: ClassId) -> Result<()> {
        let idx = self.find_index(cgroup_id).ok_or(Error::NotFound)?;
        self.groups[idx].set_classid(classid);
        Ok(())
    }

    /// Attach a PID to a cgroup group.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the group does not exist.
    /// - [`Error::OutOfMemory`] if the PID table is full.
    /// - [`Error::AlreadyExists`] if the PID is already attached.
    pub fn attach_pid(&mut self, cgroup_id: u64, pid: u64) -> Result<()> {
        let idx = self.find_index(cgroup_id).ok_or(Error::NotFound)?;
        self.groups[idx].attach_pid(pid)?;
        self.stats.pid_attaches += 1;
        Ok(())
    }

    /// Detach a PID from a cgroup group.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the group or PID does not exist.
    pub fn detach_pid(&mut self, cgroup_id: u64, pid: u64) -> Result<()> {
        let idx = self.find_index(cgroup_id).ok_or(Error::NotFound)?;
        self.groups[idx].detach_pid(pid)?;
        self.stats.pid_detaches += 1;
        Ok(())
    }

    /// Classify a packet from `pid`.
    ///
    /// Searches all active groups for the PID and returns the
    /// first matching classid. Returns `ClassId::UNCLASSIFIED` if
    /// no group claims the PID.
    pub fn classify(&mut self, pid: u64) -> ClassId {
        self.stats.classify_lookups += 1;
        for group in &mut self.groups {
            if group.state != NetClsState::Active {
                continue;
            }
            if let Some(cid) = group.classify(pid) {
                if !cid.is_unclassified() {
                    self.stats.total_classified += 1;
                }
                return cid;
            }
        }
        ClassId::UNCLASSIFIED
    }

    /// Look up a group by its identifier.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the group does not exist.
    pub fn get(&self, cgroup_id: u64) -> Result<&NetClsGroup> {
        let idx = self.find_index(cgroup_id).ok_or(Error::NotFound)?;
        Ok(&self.groups[idx])
    }

    /// Return a snapshot of global statistics.
    pub fn stats(&self) -> &NetClsCgroupStats {
        &self.stats
    }

    /// Return the number of active groups.
    pub fn active_count(&self) -> usize {
        self.active_count
    }

    // ── Private helpers ──────────────────────────────────────────

    /// Find the table index for `cgroup_id`.
    fn find_index(&self, cgroup_id: u64) -> Option<usize> {
        self.groups
            .iter()
            .position(|g| g.state != NetClsState::Free && g.cgroup_id == cgroup_id)
    }
}
