// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cgroups v2 unified hierarchy.
//!
//! Implements the Linux cgroup v2 design with a single unified
//! hierarchy, subtree control, and resource controllers (cpu, memory,
//! io, pids). Provides `cgroup_attach_task`, `cgroup_mkdir`,
//! and `cgroup_stat` operations.
//!
//! # Architecture
//!
//! ```text
//! CgroupV2Root
//!  ├── CgroupNode[MAX_CGROUPS]  (tree via parent indices)
//!  │    ├── subtree_control (bitmask of enabled controllers)
//!  │    ├── attached PIDs
//!  │    └── per-controller stats
//!  └── CgroupController[4] (cpu, memory, io, pids)
//! ```

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum cgroups in the hierarchy.
const MAX_CGROUPS: usize = 256;

/// Maximum tasks attached to a single cgroup.
const MAX_TASKS_PER_CGROUP: usize = 64;

/// Maximum children per cgroup.
const MAX_CHILDREN: usize = 32;

/// Cgroup name maximum length.
const NAME_LEN: usize = 32;

// ======================================================================
// Controller bitmask
// ======================================================================

/// Bitmask of cgroup controllers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControllerMask(pub u32);

impl ControllerMask {
    /// No controllers.
    pub const NONE: Self = Self(0);
    /// CPU controller.
    pub const CPU: Self = Self(1 << 0);
    /// Memory controller.
    pub const MEMORY: Self = Self(1 << 1);
    /// IO controller.
    pub const IO: Self = Self(1 << 2);
    /// PIDs controller.
    pub const PIDS: Self = Self(1 << 3);
    /// All controllers.
    pub const ALL: Self = Self(0x0F);

    /// Returns whether a specific controller is enabled.
    pub fn has(self, ctrl: ControllerMask) -> bool {
        self.0 & ctrl.0 != 0
    }

    /// Enables a controller.
    pub fn enable(&mut self, ctrl: ControllerMask) {
        self.0 |= ctrl.0;
    }

    /// Disables a controller.
    pub fn disable(&mut self, ctrl: ControllerMask) {
        self.0 &= !ctrl.0;
    }
}

// ======================================================================
// Cgroup type
// ======================================================================

/// Cgroup domain type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupType {
    /// Normal resource domain.
    Domain,
    /// Thread-granularity member.
    Threaded,
    /// Domain that hosts threaded children.
    DomainThreaded,
    /// Invalid transitional state.
    DomainInvalid,
}

// ======================================================================
// Per-controller statistics
// ======================================================================

/// CPU controller stats for a cgroup.
#[derive(Clone, Copy)]
pub struct CpuCtrlStats {
    /// Total CPU usage in nanoseconds.
    pub usage_ns: u64,
    /// Number of scheduler periods.
    pub nr_periods: u64,
    /// Number of throttled periods.
    pub nr_throttled: u64,
    /// Total throttled time in nanoseconds.
    pub throttled_ns: u64,
}

impl CpuCtrlStats {
    /// Creates zeroed stats.
    pub const fn new() -> Self {
        Self {
            usage_ns: 0,
            nr_periods: 0,
            nr_throttled: 0,
            throttled_ns: 0,
        }
    }
}

/// Memory controller stats for a cgroup.
#[derive(Clone, Copy)]
pub struct MemoryCtrlStats {
    /// Current memory usage in bytes.
    pub usage_bytes: u64,
    /// Memory limit in bytes (0 = unlimited).
    pub limit_bytes: u64,
    /// High watermark in bytes.
    pub high_bytes: u64,
    /// Maximum usage observed.
    pub max_usage_bytes: u64,
    /// Number of OOM events.
    pub nr_oom_events: u64,
}

impl MemoryCtrlStats {
    /// Creates zeroed stats.
    pub const fn new() -> Self {
        Self {
            usage_bytes: 0,
            limit_bytes: 0,
            high_bytes: 0,
            max_usage_bytes: 0,
            nr_oom_events: 0,
        }
    }
}

/// IO controller stats for a cgroup.
#[derive(Clone, Copy)]
pub struct IoCtrlStats {
    /// Bytes read.
    pub bytes_read: u64,
    /// Bytes written.
    pub bytes_written: u64,
    /// IO operations count.
    pub io_ops: u64,
    /// IO weight (1-10000).
    pub weight: u32,
}

impl IoCtrlStats {
    /// Creates zeroed stats.
    pub const fn new() -> Self {
        Self {
            bytes_read: 0,
            bytes_written: 0,
            io_ops: 0,
            weight: 100,
        }
    }
}

/// PIDs controller stats for a cgroup.
#[derive(Clone, Copy)]
pub struct PidsCtrlStats {
    /// Current number of PIDs in this cgroup.
    pub current: u32,
    /// Maximum allowed PIDs (0 = unlimited).
    pub limit: u32,
    /// Number of fork failures due to limit.
    pub nr_fork_fails: u64,
}

impl PidsCtrlStats {
    /// Creates zeroed stats.
    pub const fn new() -> Self {
        Self {
            current: 0,
            limit: 0,
            nr_fork_fails: 0,
        }
    }
}

// ======================================================================
// Cgroup node
// ======================================================================

/// A single cgroup node in the hierarchy.
pub struct CgroupNode {
    /// Cgroup name.
    pub name: [u8; NAME_LEN],
    /// Name length.
    pub name_len: usize,
    /// Cgroup type.
    pub cgroup_type: CgroupType,
    /// Parent cgroup index (u16::MAX for root).
    pub parent: u16,
    /// Children indices.
    children: [u16; MAX_CHILDREN],
    /// Number of children.
    pub nr_children: usize,
    /// Subtree control mask (controllers enabled for children).
    pub subtree_control: ControllerMask,
    /// Attached task PIDs.
    tasks: [u64; MAX_TASKS_PER_CGROUP],
    /// Number of attached tasks.
    pub nr_tasks: usize,
    /// Whether this node is active.
    pub active: bool,
    /// CPU controller stats.
    pub cpu_stats: CpuCtrlStats,
    /// Memory controller stats.
    pub memory_stats: MemoryCtrlStats,
    /// IO controller stats.
    pub io_stats: IoCtrlStats,
    /// PIDs controller stats.
    pub pids_stats: PidsCtrlStats,
    /// Whether frozen.
    pub frozen: bool,
    /// Generation counter for event notification.
    pub generation: u64,
}

impl CgroupNode {
    /// Creates an inactive cgroup node.
    pub const fn new() -> Self {
        Self {
            name: [0u8; NAME_LEN],
            name_len: 0,
            cgroup_type: CgroupType::Domain,
            parent: u16::MAX,
            children: [0u16; MAX_CHILDREN],
            nr_children: 0,
            subtree_control: ControllerMask::NONE,
            tasks: [0u64; MAX_TASKS_PER_CGROUP],
            nr_tasks: 0,
            active: false,
            cpu_stats: CpuCtrlStats::new(),
            memory_stats: MemoryCtrlStats::new(),
            io_stats: IoCtrlStats::new(),
            pids_stats: PidsCtrlStats::new(),
            frozen: false,
            generation: 0,
        }
    }

    /// Attaches a task PID to this cgroup.
    pub fn attach_task(&mut self, pid: u64) -> Result<()> {
        // Check for duplicate.
        if self.tasks[..self.nr_tasks].iter().any(|&p| p == pid) {
            return Err(Error::AlreadyExists);
        }
        if self.nr_tasks >= MAX_TASKS_PER_CGROUP {
            return Err(Error::OutOfMemory);
        }
        // Check PIDs limit.
        if self.pids_stats.limit > 0 && self.pids_stats.current >= self.pids_stats.limit {
            self.pids_stats.nr_fork_fails += 1;
            return Err(Error::Busy);
        }
        self.tasks[self.nr_tasks] = pid;
        self.nr_tasks += 1;
        self.pids_stats.current += 1;
        self.generation += 1;
        Ok(())
    }

    /// Detaches a task PID from this cgroup.
    pub fn detach_task(&mut self, pid: u64) -> Result<()> {
        let pos = self.tasks[..self.nr_tasks]
            .iter()
            .position(|&p| p == pid)
            .ok_or(Error::NotFound)?;
        let mut i = pos;
        while i + 1 < self.nr_tasks {
            self.tasks[i] = self.tasks[i + 1];
            i += 1;
        }
        self.nr_tasks -= 1;
        self.pids_stats.current = self.pids_stats.current.saturating_sub(1);
        self.generation += 1;
        Ok(())
    }

    /// Adds a child index.
    fn add_child(&mut self, child_idx: u16) -> Result<()> {
        if self.nr_children >= MAX_CHILDREN {
            return Err(Error::OutOfMemory);
        }
        self.children[self.nr_children] = child_idx;
        self.nr_children += 1;
        Ok(())
    }

    /// Removes a child index.
    fn remove_child(&mut self, child_idx: u16) -> bool {
        if let Some(pos) = self.children[..self.nr_children]
            .iter()
            .position(|&c| c == child_idx)
        {
            let mut j = pos;
            while j + 1 < self.nr_children {
                self.children[j] = self.children[j + 1];
                j += 1;
            }
            self.nr_children -= 1;
            true
        } else {
            false
        }
    }
}

// ======================================================================
// CgroupV2Root — top-level
// ======================================================================

/// Root of the cgroup v2 hierarchy.
pub struct CgroupV2Root {
    /// All cgroup nodes (index 0 is the root).
    nodes: [CgroupNode; MAX_CGROUPS],
    /// Number of active cgroups.
    pub nr_cgroups: u32,
    /// Global generation counter for events.
    pub generation: u64,
}

impl CgroupV2Root {
    /// Creates a cgroup v2 root hierarchy.
    pub const fn new() -> Self {
        Self {
            nodes: [const { CgroupNode::new() }; MAX_CGROUPS],
            nr_cgroups: 0,
            generation: 0,
        }
    }

    /// Initialises the root cgroup (index 0).
    pub fn init_root(&mut self) -> Result<()> {
        if self.nodes[0].active {
            return Err(Error::AlreadyExists);
        }
        self.nodes[0].active = true;
        self.nodes[0].cgroup_type = CgroupType::Domain;
        self.nodes[0].subtree_control = ControllerMask::ALL;
        self.nodes[0].parent = u16::MAX;
        let name = b"root";
        let len = name.len().min(NAME_LEN);
        self.nodes[0].name[..len].copy_from_slice(&name[..len]);
        self.nodes[0].name_len = len;
        self.nr_cgroups = 1;
        Ok(())
    }

    /// Creates a child cgroup under `parent_idx`.
    pub fn cgroup_mkdir(&mut self, parent_idx: u16, name: &[u8]) -> Result<u16> {
        let pi = parent_idx as usize;
        if pi >= MAX_CGROUPS || !self.nodes[pi].active {
            return Err(Error::NotFound);
        }
        // v2 constraint: parent with tasks cannot have children
        // (simplified — skip for threaded domains).
        if self.nodes[pi].nr_tasks > 0 && self.nodes[pi].cgroup_type == CgroupType::Domain {
            // Relax: allow if no tasks or threaded.
        }

        let slot = self
            .nodes
            .iter()
            .position(|n| !n.active)
            .ok_or(Error::OutOfMemory)?;

        let len = name.len().min(NAME_LEN);
        self.nodes[slot].name[..len].copy_from_slice(&name[..len]);
        self.nodes[slot].name_len = len;
        self.nodes[slot].active = true;
        self.nodes[slot].parent = parent_idx;
        self.nodes[slot].cgroup_type = CgroupType::Domain;
        self.nodes[slot].subtree_control = ControllerMask::NONE;
        self.nodes[slot].nr_tasks = 0;
        self.nodes[slot].nr_children = 0;
        self.nodes[slot].frozen = false;
        self.nodes[slot].generation = 0;

        self.nodes[pi].add_child(slot as u16)?;
        self.nr_cgroups += 1;
        self.generation += 1;

        Ok(slot as u16)
    }

    /// Removes a cgroup (must be empty — no tasks, no children).
    pub fn cgroup_rmdir(&mut self, idx: u16) -> Result<()> {
        let i = idx as usize;
        if i >= MAX_CGROUPS || !self.nodes[i].active {
            return Err(Error::NotFound);
        }
        if idx == 0 {
            return Err(Error::PermissionDenied); // can't remove root
        }
        if self.nodes[i].nr_tasks > 0 || self.nodes[i].nr_children > 0 {
            return Err(Error::Busy);
        }

        let parent = self.nodes[i].parent;
        if (parent as usize) < MAX_CGROUPS {
            self.nodes[parent as usize].remove_child(idx);
        }

        self.nodes[i].active = false;
        self.nr_cgroups = self.nr_cgroups.saturating_sub(1);
        self.generation += 1;
        Ok(())
    }

    /// Attaches a task to a cgroup.
    pub fn cgroup_attach_task(&mut self, cgroup_idx: u16, pid: u64) -> Result<()> {
        let i = cgroup_idx as usize;
        if i >= MAX_CGROUPS || !self.nodes[i].active {
            return Err(Error::NotFound);
        }
        self.nodes[i].attach_task(pid)?;
        self.generation += 1;
        Ok(())
    }

    /// Detaches a task from a cgroup.
    pub fn cgroup_detach_task(&mut self, cgroup_idx: u16, pid: u64) -> Result<()> {
        let i = cgroup_idx as usize;
        if i >= MAX_CGROUPS || !self.nodes[i].active {
            return Err(Error::NotFound);
        }
        self.nodes[i].detach_task(pid)?;
        self.generation += 1;
        Ok(())
    }

    /// Sets subtree control for a cgroup.
    pub fn set_subtree_control(&mut self, cgroup_idx: u16, mask: ControllerMask) -> Result<()> {
        let i = cgroup_idx as usize;
        if i >= MAX_CGROUPS || !self.nodes[i].active {
            return Err(Error::NotFound);
        }
        self.nodes[i].subtree_control = mask;
        self.generation += 1;
        Ok(())
    }

    /// Returns a summary stat for a cgroup.
    pub fn cgroup_stat(&self, cgroup_idx: u16) -> Result<CgroupStat> {
        let i = cgroup_idx as usize;
        if i >= MAX_CGROUPS || !self.nodes[i].active {
            return Err(Error::NotFound);
        }
        Ok(CgroupStat {
            nr_tasks: self.nodes[i].nr_tasks as u32,
            nr_children: self.nodes[i].nr_children as u32,
            cpu_usage_ns: self.nodes[i].cpu_stats.usage_ns,
            memory_usage_bytes: self.nodes[i].memory_stats.usage_bytes,
            io_bytes_read: self.nodes[i].io_stats.bytes_read,
            io_bytes_written: self.nodes[i].io_stats.bytes_written,
            frozen: self.nodes[i].frozen,
        })
    }

    /// Returns immutable access to a cgroup node.
    pub fn node(&self, idx: u16) -> Option<&CgroupNode> {
        let i = idx as usize;
        if i < MAX_CGROUPS && self.nodes[i].active {
            Some(&self.nodes[i])
        } else {
            None
        }
    }

    /// Returns mutable access to a cgroup node.
    pub fn node_mut(&mut self, idx: u16) -> Option<&mut CgroupNode> {
        let i = idx as usize;
        if i < MAX_CGROUPS && self.nodes[i].active {
            Some(&mut self.nodes[i])
        } else {
            None
        }
    }
}

/// Summary statistics for a cgroup.
pub struct CgroupStat {
    /// Number of attached tasks.
    pub nr_tasks: u32,
    /// Number of child cgroups.
    pub nr_children: u32,
    /// CPU usage in nanoseconds.
    pub cpu_usage_ns: u64,
    /// Memory usage in bytes.
    pub memory_usage_bytes: u64,
    /// IO bytes read.
    pub io_bytes_read: u64,
    /// IO bytes written.
    pub io_bytes_written: u64,
    /// Whether frozen.
    pub frozen: bool,
}

// ======================================================================
// Resource controllers
// ======================================================================

// ── CpuController ────────────────────────────────────────────────

/// CPU bandwidth controller implementing `cpu.max` semantics.
///
/// Enforces a quota/period bandwidth limit: the cgroup may consume
/// at most `quota_us` microseconds of CPU time per `period_us`
/// microsecond window. When the quota is exhausted the cgroup is
/// throttled until the next period.
///
/// # Interface mapping
///
/// | cgroup file   | Field           |
/// |---------------|-----------------|
/// | `cpu.max`     | quota / period  |
/// | `cpu.stat`    | usage / periods / throttled |
pub struct CpuController {
    /// Maximum CPU time allowed per period (microseconds).
    /// A value of 0 means unlimited (no bandwidth cap).
    quota_us: u64,
    /// Period length (microseconds). Default 100 000 (100 ms).
    period_us: u64,
    /// CPU time consumed in the current period (microseconds).
    used_us: u64,
    /// Total number of elapsed periods.
    nr_periods: u64,
    /// Number of periods in which the cgroup was throttled.
    nr_throttled: u64,
    /// Total throttled time (microseconds).
    throttled_us: u64,
    /// Whether the controller is currently enforcing a limit.
    enabled: bool,
}

impl CpuController {
    /// Default period length: 100 ms = 100 000 us.
    const DEFAULT_PERIOD_US: u64 = 100_000;

    /// Create a new CPU controller with no bandwidth limit.
    pub const fn new() -> Self {
        Self {
            quota_us: 0,
            period_us: Self::DEFAULT_PERIOD_US,
            used_us: 0,
            nr_periods: 0,
            nr_throttled: 0,
            throttled_us: 0,
            enabled: false,
        }
    }

    /// Set the bandwidth limit (`cpu.max` equivalent).
    ///
    /// `quota_us = 0` disables the limit. `period_us` must be > 0.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if `period_us` is zero or if
    /// `quota_us` exceeds `period_us` (over-provisioned).
    pub fn set_limit(&mut self, quota_us: u64, period_us: u64) -> Result<()> {
        if period_us == 0 {
            return Err(Error::InvalidArgument);
        }
        if quota_us > 0 && quota_us > period_us {
            return Err(Error::InvalidArgument);
        }
        self.quota_us = quota_us;
        self.period_us = period_us;
        self.enabled = quota_us > 0;
        Ok(())
    }

    /// Return the current quota and period.
    pub const fn limit(&self) -> (u64, u64) {
        (self.quota_us, self.period_us)
    }

    /// Whether the controller is actively limiting bandwidth.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Record CPU usage for this period.
    ///
    /// `delta_us` is the additional CPU time consumed since the
    /// last call. Returns `Ok(())` if usage is within budget,
    /// or `Err(Busy)` if the cgroup should be throttled.
    pub fn charge(&mut self, delta_us: u64) -> Result<()> {
        self.used_us = self.used_us.saturating_add(delta_us);
        if self.enabled && self.used_us >= self.quota_us {
            self.nr_throttled = self.nr_throttled.saturating_add(1);
            self.throttled_us = self
                .throttled_us
                .saturating_add(self.used_us.saturating_sub(self.quota_us));
            return Err(Error::Busy);
        }
        Ok(())
    }

    /// Check whether the cgroup has remaining budget in this
    /// period without consuming any.
    pub const fn check_budget(&self) -> bool {
        !self.enabled || self.used_us < self.quota_us
    }

    /// Advance to a new period: reset the usage counter and bump
    /// the period count.
    pub fn new_period(&mut self) {
        self.nr_periods = self.nr_periods.saturating_add(1);
        self.used_us = 0;
    }

    /// Return the accumulated statistics.
    pub const fn stats(&self) -> (u64, u64, u64) {
        (self.nr_periods, self.nr_throttled, self.throttled_us)
    }

    /// Apply this controller's state to a [`CpuCtrlStats`] struct.
    pub fn update_stats(&self, dst: &mut CpuCtrlStats) {
        dst.nr_periods = self.nr_periods;
        dst.nr_throttled = self.nr_throttled;
        dst.throttled_ns = self.throttled_us.saturating_mul(1_000);
    }
}

impl Default for CpuController {
    fn default() -> Self {
        Self::new()
    }
}

// ── MemoryController ─────────────────────────────────────────────

/// Memory resource controller implementing `memory.max` semantics.
///
/// Enforces a hard memory limit. When usage reaches the limit,
/// a reclaim cycle is triggered. If reclaim fails, the allocation
/// is denied and an OOM event is recorded.
///
/// | cgroup file     | Field / Method          |
/// |-----------------|-------------------------|
/// | `memory.max`    | `limit_bytes`           |
/// | `memory.high`   | `high_bytes`            |
/// | `memory.current`| `usage_bytes`           |
/// | `memory.stat`   | `stats()`               |
pub struct MemoryController {
    /// Current memory usage (bytes).
    usage_bytes: u64,
    /// Hard limit (bytes). 0 = unlimited.
    limit_bytes: u64,
    /// High watermark / soft limit (bytes). 0 = no soft limit.
    high_bytes: u64,
    /// Peak usage observed since creation (bytes).
    peak_bytes: u64,
    /// Number of OOM events (allocation denied after reclaim
    /// failure).
    nr_oom_events: u64,
    /// Number of times the high watermark was exceeded, triggering
    /// asynchronous reclaim.
    nr_high_events: u64,
    /// Whether the controller is actively limiting.
    enabled: bool,
}

impl MemoryController {
    /// Create a new memory controller with no limit.
    pub const fn new() -> Self {
        Self {
            usage_bytes: 0,
            limit_bytes: 0,
            high_bytes: 0,
            peak_bytes: 0,
            nr_oom_events: 0,
            nr_high_events: 0,
            enabled: false,
        }
    }

    /// Set the hard memory limit (`memory.max`).
    ///
    /// `limit = 0` disables the hard limit.
    pub fn set_limit(&mut self, limit: u64) {
        self.limit_bytes = limit;
        self.enabled = limit > 0;
    }

    /// Set the high watermark / soft limit (`memory.high`).
    pub fn set_high(&mut self, high: u64) {
        self.high_bytes = high;
    }

    /// Return the current limits.
    pub const fn limits(&self) -> (u64, u64) {
        (self.limit_bytes, self.high_bytes)
    }

    /// Whether the controller is actively limiting.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Attempt to charge `size` bytes of memory usage.
    ///
    /// Returns `Ok(true)` if the allocation is within the soft
    /// limit, `Ok(false)` if it exceeds the high watermark
    /// (caller should trigger async reclaim), or `Err(OutOfMemory)`
    /// if the hard limit is exceeded (OOM).
    pub fn charge(&mut self, size: u64) -> Result<bool> {
        let new_usage = self.usage_bytes.saturating_add(size);

        // Hard limit check.
        if self.enabled && new_usage > self.limit_bytes {
            self.nr_oom_events = self.nr_oom_events.saturating_add(1);
            return Err(Error::OutOfMemory);
        }

        self.usage_bytes = new_usage;
        if new_usage > self.peak_bytes {
            self.peak_bytes = new_usage;
        }

        // High watermark check.
        if self.high_bytes > 0 && new_usage > self.high_bytes {
            self.nr_high_events = self.nr_high_events.saturating_add(1);
            return Ok(false);
        }

        Ok(true)
    }

    /// Release `size` bytes of memory usage.
    pub fn uncharge(&mut self, size: u64) {
        self.usage_bytes = self.usage_bytes.saturating_sub(size);
    }

    /// Return the current usage.
    pub const fn usage(&self) -> u64 {
        self.usage_bytes
    }

    /// Return the peak usage.
    pub const fn peak(&self) -> u64 {
        self.peak_bytes
    }

    /// Check whether there is room for `size` bytes without
    /// hitting the hard limit.
    pub fn check_limit(&self, size: u64) -> bool {
        if !self.enabled {
            return true;
        }
        self.usage_bytes.saturating_add(size) <= self.limit_bytes
    }

    /// Apply this controller's state to a [`MemoryCtrlStats`].
    pub fn update_stats(&self, dst: &mut MemoryCtrlStats) {
        dst.usage_bytes = self.usage_bytes;
        dst.limit_bytes = self.limit_bytes;
        dst.high_bytes = self.high_bytes;
        dst.max_usage_bytes = self.peak_bytes;
        dst.nr_oom_events = self.nr_oom_events;
    }
}

impl Default for MemoryController {
    fn default() -> Self {
        Self::new()
    }
}

// ── IoController ─────────────────────────────────────────────────

/// Maximum number of per-device IO limits.
const MAX_IO_DEVICES: usize = 16;

/// A per-device BPS/IOPS rate limit entry.
///
/// Maps a device (identified by major:minor pair) to read/write
/// byte-per-second and IO-per-second limits.
#[derive(Clone, Copy)]
pub struct IoDeviceLimit {
    /// Device major number.
    pub major: u16,
    /// Device minor number.
    pub minor: u16,
    /// Read bytes-per-second limit (0 = unlimited).
    pub rbps: u64,
    /// Write bytes-per-second limit (0 = unlimited).
    pub wbps: u64,
    /// Read IOPS limit (0 = unlimited).
    pub riops: u32,
    /// Write IOPS limit (0 = unlimited).
    pub wiops: u32,
    /// Whether this slot is active.
    active: bool,
}

impl IoDeviceLimit {
    /// Create an empty (inactive) device limit entry.
    pub const fn new() -> Self {
        Self {
            major: 0,
            minor: 0,
            rbps: 0,
            wbps: 0,
            riops: 0,
            wiops: 0,
            active: false,
        }
    }
}

impl Default for IoDeviceLimit {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-device IO usage counters for a single accounting window.
#[derive(Clone, Copy)]
struct IoDeviceUsage {
    /// Bytes read in the current window.
    bytes_read: u64,
    /// Bytes written in the current window.
    bytes_written: u64,
    /// Read IOs in the current window.
    ios_read: u32,
    /// Write IOs in the current window.
    ios_written: u32,
}

impl IoDeviceUsage {
    const fn new() -> Self {
        Self {
            bytes_read: 0,
            bytes_written: 0,
            ios_read: 0,
            ios_written: 0,
        }
    }

    fn reset(&mut self) {
        self.bytes_read = 0;
        self.bytes_written = 0;
        self.ios_read = 0;
        self.ios_written = 0;
    }
}

/// IO resource controller implementing `io.max` semantics.
///
/// Enforces per-device BPS and IOPS limits. Each device identified
/// by (major, minor) can have independent read/write rate limits.
///
/// | cgroup file | Field / Method         |
/// |-------------|------------------------|
/// | `io.max`    | `set_device_limit()`   |
/// | `io.stat`   | `device_usage()`       |
pub struct IoController {
    /// Per-device limit entries.
    limits: [IoDeviceLimit; MAX_IO_DEVICES],
    /// Per-device usage counters (indexed same as limits).
    usage: [IoDeviceUsage; MAX_IO_DEVICES],
    /// Number of active device limit entries.
    nr_devices: usize,
    /// Whether any device has a non-zero limit.
    enabled: bool,
}

impl IoController {
    /// Create a new IO controller with no device limits.
    pub const fn new() -> Self {
        Self {
            limits: [const { IoDeviceLimit::new() }; MAX_IO_DEVICES],
            usage: [const { IoDeviceUsage::new() }; MAX_IO_DEVICES],
            nr_devices: 0,
            enabled: false,
        }
    }

    /// Set or update a per-device rate limit (`io.max`).
    ///
    /// If a limit already exists for `(major, minor)` it is
    /// updated in place. Otherwise a new entry is allocated.
    ///
    /// # Errors
    ///
    /// Returns `OutOfMemory` if no free slots remain.
    pub fn set_device_limit(
        &mut self,
        major: u16,
        minor: u16,
        rbps: u64,
        wbps: u64,
        riops: u32,
        wiops: u32,
    ) -> Result<()> {
        // Check for existing entry.
        for i in 0..self.nr_devices {
            if self.limits[i].active
                && self.limits[i].major == major
                && self.limits[i].minor == minor
            {
                self.limits[i].rbps = rbps;
                self.limits[i].wbps = wbps;
                self.limits[i].riops = riops;
                self.limits[i].wiops = wiops;
                self.refresh_enabled();
                return Ok(());
            }
        }

        // Allocate new slot.
        if self.nr_devices >= MAX_IO_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let slot = self.nr_devices;
        self.limits[slot] = IoDeviceLimit {
            major,
            minor,
            rbps,
            wbps,
            riops,
            wiops,
            active: true,
        };
        self.usage[slot] = IoDeviceUsage::new();
        self.nr_devices += 1;
        self.refresh_enabled();
        Ok(())
    }

    /// Remove a per-device rate limit.
    ///
    /// Returns `NotFound` if no limit exists for the device.
    pub fn remove_device_limit(&mut self, major: u16, minor: u16) -> Result<()> {
        let pos = self.find_device(major, minor).ok_or(Error::NotFound)?;
        // Shift remaining entries down.
        let mut i = pos;
        while i + 1 < self.nr_devices {
            self.limits[i] = self.limits[i + 1];
            self.usage[i] = self.usage[i + 1];
            i += 1;
        }
        self.nr_devices -= 1;
        self.refresh_enabled();
        Ok(())
    }

    /// Check whether a read IO of `bytes` to device `(major,minor)`
    /// is within the rate limit.
    ///
    /// Returns `Ok(())` if allowed, `Err(Busy)` if throttled.
    pub fn check_read(&self, major: u16, minor: u16, bytes: u64) -> Result<()> {
        if let Some(idx) = self.find_device(major, minor) {
            let lim = &self.limits[idx];
            let usg = &self.usage[idx];
            if lim.rbps > 0 && usg.bytes_read.saturating_add(bytes) > lim.rbps {
                return Err(Error::Busy);
            }
            if lim.riops > 0 && usg.ios_read >= lim.riops {
                return Err(Error::Busy);
            }
        }
        Ok(())
    }

    /// Check whether a write IO of `bytes` to device
    /// `(major,minor)` is within the rate limit.
    ///
    /// Returns `Ok(())` if allowed, `Err(Busy)` if throttled.
    pub fn check_write(&self, major: u16, minor: u16, bytes: u64) -> Result<()> {
        if let Some(idx) = self.find_device(major, minor) {
            let lim = &self.limits[idx];
            let usg = &self.usage[idx];
            if lim.wbps > 0 && usg.bytes_written.saturating_add(bytes) > lim.wbps {
                return Err(Error::Busy);
            }
            if lim.wiops > 0 && usg.ios_written >= lim.wiops {
                return Err(Error::Busy);
            }
        }
        Ok(())
    }

    /// Record a completed read IO.
    pub fn charge_read(&mut self, major: u16, minor: u16, bytes: u64) {
        if let Some(idx) = self.find_device(major, minor) {
            self.usage[idx].bytes_read = self.usage[idx].bytes_read.saturating_add(bytes);
            self.usage[idx].ios_read = self.usage[idx].ios_read.saturating_add(1);
        }
    }

    /// Record a completed write IO.
    pub fn charge_write(&mut self, major: u16, minor: u16, bytes: u64) {
        if let Some(idx) = self.find_device(major, minor) {
            self.usage[idx].bytes_written = self.usage[idx].bytes_written.saturating_add(bytes);
            self.usage[idx].ios_written = self.usage[idx].ios_written.saturating_add(1);
        }
    }

    /// Reset all per-device usage counters (start of a new
    /// accounting window).
    pub fn reset_usage(&mut self) {
        for usg in &mut self.usage[..self.nr_devices] {
            usg.reset();
        }
    }

    /// Whether the controller has any active rate limits.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Return the number of devices with active limits.
    pub const fn device_count(&self) -> usize {
        self.nr_devices
    }

    /// Return the limit entry for a device, if configured.
    pub fn device_limit(&self, major: u16, minor: u16) -> Option<&IoDeviceLimit> {
        self.find_device(major, minor).map(|idx| &self.limits[idx])
    }

    /// Apply aggregate IO statistics to an [`IoCtrlStats`].
    pub fn update_stats(&self, dst: &mut IoCtrlStats) {
        let mut total_read = 0u64;
        let mut total_written = 0u64;
        let mut total_ops = 0u64;
        for usg in &self.usage[..self.nr_devices] {
            total_read = total_read.saturating_add(usg.bytes_read);
            total_written = total_written.saturating_add(usg.bytes_written);
            total_ops = total_ops
                .saturating_add(usg.ios_read as u64)
                .saturating_add(usg.ios_written as u64);
        }
        dst.bytes_read = total_read;
        dst.bytes_written = total_written;
        dst.io_ops = total_ops;
    }

    /// Find the index of a device entry by (major, minor).
    fn find_device(&self, major: u16, minor: u16) -> Option<usize> {
        self.limits[..self.nr_devices]
            .iter()
            .position(|l| l.active && l.major == major && l.minor == minor)
    }

    /// Recalculate the `enabled` flag based on current limits.
    fn refresh_enabled(&mut self) {
        self.enabled = self.limits[..self.nr_devices]
            .iter()
            .any(|l| l.active && (l.rbps > 0 || l.wbps > 0 || l.riops > 0 || l.wiops > 0));
    }
}

impl Default for IoController {
    fn default() -> Self {
        Self::new()
    }
}
