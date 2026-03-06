// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Control groups (cgroups) v2 resource control.
//!
//! Provides hierarchical resource management for processes, compatible
//! with the Linux cgroups v2 unified hierarchy model. Each cgroup can
//! limit CPU, memory, I/O, and PID resources for its member
//! processes.
//!
//! Cgroups are managed via the cgroupfs virtual filesystem rather
//! than direct system calls. The kernel exposes a flat registry of
//! cgroups organized in a tree (parent/child relationships) with
//! the root cgroup always at index 0.
//!
//! Reference: Linux kernel `Documentation/admin-guide/cgroup-v2.rst`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum number of cgroups in the system.
const MAX_CGROUPS: usize = 32;

/// Maximum number of member PIDs per cgroup.
const MAX_MEMBERS: usize = 64;

/// Maximum cgroup name length in bytes.
const MAX_NAME_LEN: usize = 64;

/// Default CPU weight (cgroups v2 range: 1-10000, default 100).
const DEFAULT_CPU_WEIGHT: u32 = 100;

/// Minimum CPU weight.
const MIN_CPU_WEIGHT: u32 = 1;

/// Maximum CPU weight.
const MAX_CPU_WEIGHT: u32 = 10_000;

/// Default CPU period in microseconds (100 ms).
const DEFAULT_CPU_PERIOD_USEC: u64 = 100_000;

/// Default maximum PIDs per cgroup.
const DEFAULT_MAX_PIDS: u32 = 4096;

// ── Controller type enum ───────────────────────────────────────────

/// Resource controller types available in the cgroups v2 hierarchy.
///
/// Each controller manages a specific class of system resources
/// and can be independently enabled or configured per cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupController {
    /// CPU time distribution (proportional weight, bandwidth cap).
    Cpu,
    /// Physical memory usage limits and accounting.
    Memory,
    /// Block I/O bandwidth and IOPS throttling.
    Io,
    /// Process/thread count limits.
    Pids,
}

impl core::fmt::Display for CgroupController {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Cpu => write!(f, "cpu"),
            Self::Memory => write!(f, "memory"),
            Self::Io => write!(f, "io"),
            Self::Pids => write!(f, "pids"),
        }
    }
}

// ── CPU controller ─────────────────────────────────────────────────

/// CPU resource controller.
///
/// Controls CPU time distribution using a proportional weight model
/// and optional bandwidth limiting (max microseconds per period).
///
/// - `weight`: proportional share (1-10000, default 100)
/// - `max_usec`: maximum CPU time in microseconds per `period_usec`
///   (`u64::MAX` means unlimited)
/// - `period_usec`: scheduling period length (default 100 ms)
#[derive(Debug, Clone, Copy)]
pub struct CpuController {
    /// Proportional CPU weight (1-10000).
    pub weight: u32,
    /// Maximum CPU time per period in microseconds.
    pub max_usec: u64,
    /// Period length in microseconds.
    pub period_usec: u64,
}

impl CpuController {
    /// Create a CPU controller with default settings.
    pub const fn new() -> Self {
        Self {
            weight: DEFAULT_CPU_WEIGHT,
            max_usec: u64::MAX,
            period_usec: DEFAULT_CPU_PERIOD_USEC,
        }
    }
}

impl Default for CpuController {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Display for CpuController {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "CpuController {{ weight: {}, period: {}us }}",
            self.weight, self.period_usec,
        )
    }
}

// ── Memory controller ──────────────────────────────────────────────

/// Memory resource controller.
///
/// Tracks and limits physical memory usage for a cgroup.
///
/// - `max_bytes`: hard limit; allocation fails above this
/// - `high_bytes`: soft/high watermark; triggers reclaim pressure
/// - `current_bytes`: currently charged memory
/// - `swap_max`: maximum swap usage in bytes
#[derive(Debug, Clone, Copy)]
pub struct MemoryController {
    /// Hard memory limit in bytes (`u64::MAX` = unlimited).
    pub max_bytes: u64,
    /// Current memory usage in bytes.
    pub current_bytes: u64,
    /// High watermark in bytes (triggers reclaim above this).
    pub high_bytes: u64,
    /// Maximum swap usage in bytes (`u64::MAX` = unlimited).
    pub swap_max: u64,
}

impl MemoryController {
    /// Create a memory controller with default (unlimited) settings.
    pub const fn new() -> Self {
        Self {
            max_bytes: u64::MAX,
            current_bytes: 0,
            high_bytes: u64::MAX,
            swap_max: u64::MAX,
        }
    }
}

impl Default for MemoryController {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Display for MemoryController {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "MemoryController {{ current: {} bytes }}",
            self.current_bytes,
        )
    }
}

// ── I/O controller ─────────────────────────────────────────────────

/// I/O resource controller.
///
/// Throttles block I/O bandwidth and IOPS for a cgroup.
/// A value of `u64::MAX` means no limit for that parameter.
#[derive(Debug, Clone, Copy)]
pub struct IoController {
    /// Maximum read bytes per second (`u64::MAX` = unlimited).
    pub read_bps_max: u64,
    /// Maximum write bytes per second (`u64::MAX` = unlimited).
    pub write_bps_max: u64,
    /// Maximum read I/O operations per second (`u64::MAX` = unlimited).
    pub read_iops_max: u64,
    /// Maximum write I/O operations per second (`u64::MAX` = unlimited).
    pub write_iops_max: u64,
}

impl IoController {
    /// Create an I/O controller with no limits.
    pub const fn new() -> Self {
        Self {
            read_bps_max: u64::MAX,
            write_bps_max: u64::MAX,
            read_iops_max: u64::MAX,
            write_iops_max: u64::MAX,
        }
    }
}

impl Default for IoController {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Display for IoController {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "IoController")
    }
}

// ── PIDs controller ────────────────────────────────────────────────

/// PIDs resource controller.
///
/// Limits the number of processes/threads within a cgroup to prevent
/// fork bombs and uncontrolled process creation.
#[derive(Debug, Clone, Copy)]
pub struct PidsController {
    /// Maximum allowed PIDs in this cgroup.
    pub max_pids: u32,
    /// Current number of PIDs in this cgroup.
    pub current_pids: u32,
}

impl PidsController {
    /// Create a PIDs controller with the default limit.
    pub const fn new() -> Self {
        Self {
            max_pids: DEFAULT_MAX_PIDS,
            current_pids: 0,
        }
    }
}

impl Default for PidsController {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Display for PidsController {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "PidsController {{ {}/{} }}",
            self.current_pids, self.max_pids,
        )
    }
}

// ── Cgroup ─────────────────────────────────────────────────────────

/// A control group — a named node in the cgroup hierarchy.
///
/// Each cgroup contains resource controllers (CPU, memory, I/O, PIDs)
/// and a list of member process IDs. Cgroups form a tree with
/// a single root; resource limits are inherited and enforced
/// hierarchically.
#[derive(Debug, Clone)]
pub struct Cgroup {
    /// Unique cgroup identifier (index in the registry).
    id: u32,
    /// Cgroup name (null-padded, UTF-8).
    name: [u8; MAX_NAME_LEN],
    /// Length of the name in bytes.
    name_len: usize,
    /// Parent cgroup ID (`None` for the root cgroup).
    parent_id: Option<u32>,
    /// CPU resource controller.
    pub cpu: CpuController,
    /// Memory resource controller.
    pub memory: MemoryController,
    /// I/O resource controller.
    pub io: IoController,
    /// PIDs resource controller.
    pub pids: PidsController,
    /// Member process IDs.
    member_pids: [u64; MAX_MEMBERS],
    /// Number of member PIDs currently registered.
    member_count: usize,
    /// Whether this cgroup is active.
    active: bool,
}

impl Cgroup {
    /// Create a new cgroup with the given ID, name, and parent.
    ///
    /// Returns `Error::InvalidArgument` if `name` is empty or
    /// exceeds [`MAX_NAME_LEN`] bytes.
    pub fn new(id: u32, name: &[u8], parent_id: Option<u32>) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut name_buf = [0u8; MAX_NAME_LEN];
        name_buf[..name.len()].copy_from_slice(name);

        Ok(Self {
            id,
            name: name_buf,
            name_len: name.len(),
            parent_id,
            cpu: CpuController::new(),
            memory: MemoryController::new(),
            io: IoController::new(),
            pids: PidsController::new(),
            member_pids: [0u64; MAX_MEMBERS],
            member_count: 0,
            active: true,
        })
    }

    /// Return the cgroup's unique identifier.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Return the cgroup name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the parent cgroup ID, or `None` for root.
    pub fn parent_id(&self) -> Option<u32> {
        self.parent_id
    }

    /// Return whether this cgroup is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Return the number of member PIDs.
    pub fn member_count(&self) -> usize {
        self.member_count
    }

    /// Return the member PIDs as a slice.
    pub fn member_pids(&self) -> &[u64] {
        &self.member_pids[..self.member_count]
    }

    /// Add a process ID to this cgroup.
    ///
    /// Returns `Error::OutOfMemory` if the member list is full,
    /// or `Error::AlreadyExists` if the PID is already a member.
    pub fn add_pid(&mut self, pid: u64) -> Result<()> {
        // Check for duplicate.
        for i in 0..self.member_count {
            if self.member_pids[i] == pid {
                return Err(Error::AlreadyExists);
            }
        }
        if self.member_count >= MAX_MEMBERS {
            return Err(Error::OutOfMemory);
        }
        self.member_pids[self.member_count] = pid;
        self.member_count = self.member_count.saturating_add(1);
        self.pids.current_pids = self.pids.current_pids.saturating_add(1);
        Ok(())
    }

    /// Remove a process ID from this cgroup.
    ///
    /// Returns `Error::NotFound` if the PID is not a member.
    pub fn remove_pid(&mut self, pid: u64) -> Result<()> {
        for i in 0..self.member_count {
            if self.member_pids[i] == pid {
                // Swap-remove: move the last element into the gap.
                let last = self.member_count.saturating_sub(1);
                self.member_pids[i] = self.member_pids[last];
                self.member_pids[last] = 0;
                self.member_count = self.member_count.saturating_sub(1);
                self.pids.current_pids = self.pids.current_pids.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Set the CPU weight for this cgroup.
    ///
    /// The weight must be in the range 1-10000. Returns
    /// `Error::InvalidArgument` if out of range.
    pub fn set_cpu_weight(&mut self, weight: u32) -> Result<()> {
        if !(MIN_CPU_WEIGHT..=MAX_CPU_WEIGHT).contains(&weight) {
            return Err(Error::InvalidArgument);
        }
        self.cpu.weight = weight;
        Ok(())
    }

    /// Set the memory hard limit for this cgroup.
    ///
    /// Use `u64::MAX` for unlimited. The limit must be greater than
    /// or equal to the current usage; returns `Error::Busy` if the
    /// current usage already exceeds the requested limit.
    pub fn set_memory_max(&mut self, max_bytes: u64) -> Result<()> {
        if max_bytes < self.memory.current_bytes {
            return Err(Error::Busy);
        }
        self.memory.max_bytes = max_bytes;
        Ok(())
    }

    /// Set the maximum PID count for this cgroup.
    ///
    /// The limit must be at least 1 and must not be lower than the
    /// current PID count. Returns `Error::InvalidArgument` if
    /// `max_pids` is zero, or `Error::Busy` if the current count
    /// already exceeds the requested limit.
    pub fn set_pids_max(&mut self, max_pids: u32) -> Result<()> {
        if max_pids == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.pids.current_pids > max_pids {
            return Err(Error::Busy);
        }
        self.pids.max_pids = max_pids;
        Ok(())
    }

    /// Check whether the cgroup can accept another PID.
    ///
    /// Returns `true` if `current_pids < max_pids`.
    pub fn check_pids_limit(&self) -> bool {
        self.pids.current_pids < self.pids.max_pids
    }

    /// Charge `bytes` of memory to this cgroup.
    ///
    /// Returns `Error::OutOfMemory` if the charge would exceed
    /// `memory.max_bytes`.
    pub fn charge_memory(&mut self, bytes: u64) -> Result<()> {
        let new_usage = self
            .memory
            .current_bytes
            .checked_add(bytes)
            .ok_or(Error::OutOfMemory)?;
        if new_usage > self.memory.max_bytes {
            return Err(Error::OutOfMemory);
        }
        self.memory.current_bytes = new_usage;
        Ok(())
    }

    /// Uncharge `bytes` of memory from this cgroup.
    ///
    /// Uses saturating subtraction so uncharging more than the
    /// current usage safely clamps to zero.
    pub fn uncharge_memory(&mut self, bytes: u64) {
        self.memory.current_bytes = self.memory.current_bytes.saturating_sub(bytes);
    }

    /// Deactivate this cgroup.
    fn deactivate(&mut self) {
        self.active = false;
    }
}

impl core::fmt::Display for Cgroup {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Cgroup {{ id: {}, members: {} }}",
            self.id, self.member_count,
        )
    }
}

// ── Cgroup registry ────────────────────────────────────────────────

/// System-wide cgroup registry.
///
/// Manages up to [`MAX_CGROUPS`] cgroups in a flat array with
/// tree structure encoded via `parent_id` references. The root
/// cgroup is always at index 0 and cannot be destroyed.
pub struct CgroupRegistry {
    /// Fixed-size array of cgroup slots.
    cgroups: [Option<Cgroup>; MAX_CGROUPS],
    /// Next cgroup ID to allocate (monotonically increasing).
    next_id: u32,
}

impl CgroupRegistry {
    /// Create a new registry with a root cgroup at index 0.
    ///
    /// The root cgroup is named `"/"` and has no parent.
    pub fn new() -> Self {
        const NONE_CGROUP: Option<Cgroup> = None;
        let mut cgroups = [NONE_CGROUP; MAX_CGROUPS];

        // Root cgroup at slot 0 — safe: b"/" is 1 byte, within
        // MAX_NAME_LEN, so `Cgroup::new` cannot fail here.
        let mut root = match Cgroup::new(0, b"/", None) {
            Ok(cg) => cg,
            Err(_) => {
                // Unreachable: name b"/" is valid. Provide a
                // minimal fallback to avoid panic.
                let mut cg_name = [0u8; MAX_NAME_LEN];
                cg_name[0] = b'/';
                Cgroup {
                    id: 0,
                    name: cg_name,
                    name_len: 1,
                    parent_id: None,
                    cpu: CpuController::new(),
                    memory: MemoryController::new(),
                    io: IoController::new(),
                    pids: PidsController::new(),
                    member_pids: [0u64; MAX_MEMBERS],
                    member_count: 0,
                    active: true,
                }
            }
        };
        // Root cgroup has no PID limit by default.
        root.pids.max_pids = u32::MAX;
        cgroups[0] = Some(root);

        Self {
            cgroups,
            next_id: 1,
        }
    }

    /// Create a child cgroup under `parent_id`.
    ///
    /// Returns the new cgroup's ID on success.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — `parent_id` does not exist or is
    ///   inactive.
    /// - `Error::InvalidArgument` — `name` is empty or too long.
    /// - `Error::OutOfMemory` — no free slots in the registry.
    pub fn create(&mut self, parent_id: u32, name: &[u8]) -> Result<u32> {
        // Validate parent exists and is active.
        let parent = self.get(parent_id).ok_or(Error::NotFound)?;
        if !parent.is_active() {
            return Err(Error::NotFound);
        }

        // Find a free slot.
        let slot = self
            .cgroups
            .iter()
            .position(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);

        let cg = Cgroup::new(id, name, Some(parent_id))?;
        self.cgroups[slot] = Some(cg);
        Ok(id)
    }

    /// Destroy a cgroup by ID.
    ///
    /// The root cgroup (ID 0) cannot be destroyed. The cgroup must
    /// have no remaining member PIDs and no active children.
    ///
    /// # Errors
    ///
    /// - `Error::PermissionDenied` — attempted to destroy the root
    ///   cgroup.
    /// - `Error::NotFound` — cgroup does not exist.
    /// - `Error::Busy` — cgroup still has members or active
    ///   children.
    pub fn destroy(&mut self, id: u32) -> Result<()> {
        if id == 0 {
            return Err(Error::PermissionDenied);
        }

        // Check the cgroup exists.
        let cg = self.get(id).ok_or(Error::NotFound)?;
        if !cg.is_active() {
            return Err(Error::NotFound);
        }
        if cg.member_count() > 0 {
            return Err(Error::Busy);
        }

        // Check for active children.
        for child in self.cgroups.iter().flatten() {
            if child.parent_id == Some(id) && child.active {
                return Err(Error::Busy);
            }
        }

        // Deactivate.
        for cg in self.cgroups.iter_mut().flatten() {
            if cg.id == id {
                cg.deactivate();
                return Ok(());
            }
        }

        Err(Error::NotFound)
    }

    /// Look up a cgroup by ID (immutable).
    pub fn get(&self, id: u32) -> Option<&Cgroup> {
        self.cgroups
            .iter()
            .flatten()
            .find(|cg| cg.id == id && cg.active)
    }

    /// Look up a cgroup by ID (mutable).
    pub fn get_mut(&mut self, id: u32) -> Option<&mut Cgroup> {
        self.cgroups
            .iter_mut()
            .flatten()
            .find(|cg| cg.id == id && cg.active)
    }

    /// Attach a PID to a cgroup.
    ///
    /// Validates the PID limit before adding.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — cgroup does not exist or is inactive.
    /// - `Error::Busy` — PID limit would be exceeded.
    /// - `Error::OutOfMemory` — member list is full.
    /// - `Error::AlreadyExists` — PID is already a member.
    pub fn attach_pid(&mut self, cgroup_id: u32, pid: u64) -> Result<()> {
        let cg = self.get_mut(cgroup_id).ok_or(Error::NotFound)?;
        if !cg.check_pids_limit() {
            return Err(Error::Busy);
        }
        cg.add_pid(pid)
    }

    /// Detach a PID from a cgroup.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — cgroup does not exist, is inactive,
    ///   or the PID is not a member.
    pub fn detach_pid(&mut self, cgroup_id: u32, pid: u64) -> Result<()> {
        let cg = self.get_mut(cgroup_id).ok_or(Error::NotFound)?;
        cg.remove_pid(pid)
    }
}

impl Default for CgroupRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for CgroupRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let active = self.cgroups.iter().flatten().filter(|cg| cg.active).count();
        f.debug_struct("CgroupRegistry")
            .field("active_cgroups", &active)
            .field("capacity", &MAX_CGROUPS)
            .finish()
    }
}
