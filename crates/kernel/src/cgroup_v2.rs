// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cgroup v2 unified hierarchy implementation.
//!
//! Implements the Linux cgroup v2 design with a single unified hierarchy,
//! subtree control, domain/threaded cgroup types, and delegation support.
//! This is the modern cgroup interface replacing the v1 multi-hierarchy
//! model.
//!
//! # Key Design Principles
//!
//! - **Unified hierarchy**: Single tree rooted at `/sys/fs/cgroup`.
//! - **Subtree control**: Controllers are enabled per-subtree via
//!   `cgroup.subtree_control`, not per-cgroup.
//! - **No internal process constraint**: A cgroup with children cannot
//!   have its own processes (with threaded-domain exceptions).
//! - **Delegation**: Subtrees can be delegated to unprivileged users.
//!
//! # Cgroup Types
//!
//! | Type            | Description                                         |
//! |-----------------|-----------------------------------------------------|
//! | Domain          | Normal resource domain (processes + controllers)    |
//! | Threaded        | Thread-granularity member of a threaded domain      |
//! | DomainThreaded  | Domain that hosts threaded children                 |
//! | DomainInvalid   | Transitional state during type conversion           |
//!
//! # Controllers
//!
//! | Controller | Description                          |
//! |------------|--------------------------------------|
//! | cpu        | CPU time distribution (weight/max)   |
//! | memory     | Memory usage limits and accounting   |
//! | io         | Block I/O bandwidth limits           |
//! | pids       | Process count limits                 |
//! | cpuset     | CPU/memory-node pinning              |
//! | rdma       | RDMA resource limits                 |
//! | misc       | Miscellaneous scalar resources       |
//!
//! # Reference
//!
//! Linux kernel `Documentation/admin-guide/cgroup-v2.rst`.
//! Linux kernel `kernel/cgroup/cgroup.c`.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum depth of the cgroup hierarchy tree.
const MAX_DEPTH: usize = 16;

/// Maximum number of cgroups in the system.
const MAX_CGROUPS: usize = 256;

/// Maximum number of children per cgroup.
const MAX_CHILDREN: usize = 32;

/// Maximum number of processes per cgroup.
const MAX_PROCS: usize = 64;

/// Maximum number of threads per threaded cgroup.
const MAX_THREADS: usize = 128;

/// Maximum cgroup name length.
const MAX_NAME_LEN: usize = 64;

/// Total number of available controller types.
const NUM_CONTROLLERS: usize = 7;

/// Default CPU weight (cgroup v2 range 1-10000).
const DEFAULT_CPU_WEIGHT: u32 = 100;

/// Maximum CPU weight.
const _MAX_CPU_WEIGHT: u32 = 10_000;

/// Default memory limit (unlimited).
const MEMORY_MAX_UNLIMITED: u64 = u64::MAX;

/// Default PIDs limit (unlimited).
const PIDS_MAX_UNLIMITED: u32 = u32::MAX;

/// PSI tracking window size in microseconds (10 seconds).
const PSI_WINDOW_US: u64 = 10_000_000;

// ── CgroupType ────────────────────────────────────────────────────────────────

/// Cgroup type in the v2 unified hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CgroupType {
    /// Normal resource domain.
    #[default]
    Domain,
    /// Thread-granularity cgroup (child of a DomainThreaded parent).
    Threaded,
    /// Domain that hosts threaded children.
    DomainThreaded,
    /// Transitional invalid state during type changes.
    DomainInvalid,
}

// ── ControllerType ────────────────────────────────────────────────────────────

/// Available resource controllers in the v2 hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControllerType {
    /// CPU time distribution.
    Cpu,
    /// Memory usage limits.
    Memory,
    /// Block I/O bandwidth.
    Io,
    /// Process count limits.
    Pids,
    /// CPU/memory-node assignment.
    Cpuset,
    /// RDMA resource limits.
    Rdma,
    /// Miscellaneous scalar resources.
    Misc,
}

impl ControllerType {
    /// Get the string name for the controller.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Memory => "memory",
            Self::Io => "io",
            Self::Pids => "pids",
            Self::Cpuset => "cpuset",
            Self::Rdma => "rdma",
            Self::Misc => "misc",
        }
    }

    /// Check if this controller supports threaded mode.
    pub const fn supports_threaded(&self) -> bool {
        matches!(self, Self::Cpu | Self::Cpuset)
    }
}

// ── ControllerMask ────────────────────────────────────────────────────────────

/// Bitmask of enabled controllers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ControllerMask(u8);

impl ControllerMask {
    /// Empty mask (no controllers).
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Enable a controller.
    pub const fn with(self, ctrl: ControllerType) -> Self {
        Self(self.0 | (1 << ctrl as u8))
    }

    /// Disable a controller.
    pub const fn without(self, ctrl: ControllerType) -> Self {
        Self(self.0 & !(1 << ctrl as u8))
    }

    /// Check if a controller is enabled.
    pub const fn has(&self, ctrl: ControllerType) -> bool {
        (self.0 & (1 << ctrl as u8)) != 0
    }

    /// Check if mask is empty.
    pub const fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// Intersection of two masks.
    pub const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Union of two masks.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Count of enabled controllers.
    pub const fn count(&self) -> usize {
        self.0.count_ones() as usize
    }
}

// ── PsiStats ──────────────────────────────────────────────────────────────────

/// Pressure Stall Information for a cgroup.
///
/// PSI measures the amount of time tasks spend waiting for resources.
/// "some" = at least one task stalled, "full" = all tasks stalled.
#[derive(Debug, Clone, Copy)]
pub struct PsiStats {
    /// Total stall time when at least one task was waiting (us).
    pub some_total_us: u64,
    /// Total stall time when all tasks were waiting (us).
    pub full_total_us: u64,
    /// Average "some" pressure over 10-second window (0-100).
    pub some_avg10: u32,
    /// Average "some" pressure over 60-second window.
    pub some_avg60: u32,
    /// Average "some" pressure over 300-second window.
    pub some_avg300: u32,
    /// Average "full" pressure over 10-second window.
    pub full_avg10: u32,
    /// Average "full" pressure over 60-second window.
    pub full_avg60: u32,
    /// Average "full" pressure over 300-second window.
    pub full_avg300: u32,
}

impl PsiStats {
    /// Create zeroed PSI stats.
    pub const fn new() -> Self {
        Self {
            some_total_us: 0,
            full_total_us: 0,
            some_avg10: 0,
            some_avg60: 0,
            some_avg300: 0,
            full_avg10: 0,
            full_avg60: 0,
            full_avg300: 0,
        }
    }

    /// Update PSI stats with a new stall sample.
    pub fn record_stall(&mut self, some_us: u64, full_us: u64, _window_us: u64) {
        self.some_total_us = self.some_total_us.saturating_add(some_us);
        self.full_total_us = self.full_total_us.saturating_add(full_us);
    }
}

impl Default for PsiStats {
    fn default() -> Self {
        Self::new()
    }
}

// ── CgroupStat ────────────────────────────────────────────────────────────────

/// Cgroup statistics (`cgroup.stat`).
#[derive(Debug, Clone, Copy)]
pub struct CgroupStat {
    /// Number of live descendants (sub-cgroups).
    pub nr_descendants: u32,
    /// Number of dying descendants (being removed).
    pub nr_dying_descendants: u32,
}

impl CgroupStat {
    /// Create zeroed stats.
    pub const fn new() -> Self {
        Self {
            nr_descendants: 0,
            nr_dying_descendants: 0,
        }
    }
}

impl Default for CgroupStat {
    fn default() -> Self {
        Self::new()
    }
}

// ── CgroupEvents ──────────────────────────────────────────────────────────────

/// Cgroup event counters (`cgroup.events`).
#[derive(Debug, Clone, Copy)]
pub struct CgroupEvents {
    /// Whether the cgroup has been "populated" (has live processes).
    pub populated: bool,
    /// Whether the cgroup has been "frozen" (all tasks frozen).
    pub frozen: bool,
}

impl CgroupEvents {
    /// Create default events.
    pub const fn new() -> Self {
        Self {
            populated: false,
            frozen: false,
        }
    }
}

impl Default for CgroupEvents {
    fn default() -> Self {
        Self::new()
    }
}

// ── CpuConfig ─────────────────────────────────────────────────────────────────

/// CPU controller configuration for a cgroup.
#[derive(Debug, Clone, Copy)]
pub struct CpuConfig {
    /// Proportional weight (1-10000, default 100).
    pub weight: u32,
    /// Nice-derived weight for backward compatibility.
    pub weight_nice: i32,
    /// Maximum bandwidth: quota microseconds per period.
    /// 0 = unlimited.
    pub max_us: u64,
    /// Bandwidth period microseconds.
    pub period_us: u64,
}

impl CpuConfig {
    /// Create a default CPU configuration.
    pub const fn new() -> Self {
        Self {
            weight: DEFAULT_CPU_WEIGHT,
            weight_nice: 0,
            max_us: 0,
            period_us: 100_000,
        }
    }
}

impl Default for CpuConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ── MemoryConfig ──────────────────────────────────────────────────────────────

/// Memory controller configuration for a cgroup.
#[derive(Debug, Clone, Copy)]
pub struct MemoryConfig {
    /// Minimum guaranteed memory (bytes).
    pub min_bytes: u64,
    /// Low watermark — best-effort minimum (bytes).
    pub low_bytes: u64,
    /// High watermark — throttle reclaim target (bytes).
    pub high_bytes: u64,
    /// Hard limit — OOM kill if exceeded (bytes).
    pub max_bytes: u64,
    /// Swap limit (bytes).
    pub swap_max_bytes: u64,
    /// Current memory usage (bytes).
    pub current_bytes: u64,
    /// OOM kill counter.
    pub oom_kills: u64,
}

impl MemoryConfig {
    /// Create default memory configuration (unlimited).
    pub const fn new() -> Self {
        Self {
            min_bytes: 0,
            low_bytes: 0,
            high_bytes: MEMORY_MAX_UNLIMITED,
            max_bytes: MEMORY_MAX_UNLIMITED,
            swap_max_bytes: MEMORY_MAX_UNLIMITED,
            current_bytes: 0,
            oom_kills: 0,
        }
    }
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ── IoConfig ──────────────────────────────────────────────────────────────────

/// I/O controller configuration for a cgroup.
#[derive(Debug, Clone, Copy)]
pub struct IoConfig {
    /// Proportional weight (1-10000, default 100).
    pub weight: u32,
    /// Maximum read bandwidth (bytes/sec, 0=unlimited).
    pub rbps_max: u64,
    /// Maximum write bandwidth (bytes/sec, 0=unlimited).
    pub wbps_max: u64,
    /// Maximum read IOPS (0=unlimited).
    pub riops_max: u32,
    /// Maximum write IOPS (0=unlimited).
    pub wiops_max: u32,
}

impl IoConfig {
    /// Create default I/O configuration (unlimited).
    pub const fn new() -> Self {
        Self {
            weight: 100,
            rbps_max: 0,
            wbps_max: 0,
            riops_max: 0,
            wiops_max: 0,
        }
    }
}

impl Default for IoConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ── PidsConfig ────────────────────────────────────────────────────────────────

/// PIDs controller configuration for a cgroup.
#[derive(Debug, Clone, Copy)]
pub struct PidsConfig {
    /// Maximum number of processes (u32::MAX = unlimited).
    pub max: u32,
    /// Current count of live processes.
    pub current: u32,
}

impl PidsConfig {
    /// Create default PID configuration.
    pub const fn new() -> Self {
        Self {
            max: PIDS_MAX_UNLIMITED,
            current: 0,
        }
    }

    /// Check if the limit has been reached.
    pub const fn is_at_limit(&self) -> bool {
        self.max != PIDS_MAX_UNLIMITED && self.current >= self.max
    }
}

impl Default for PidsConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ── DelegationConfig ──────────────────────────────────────────────────────────

/// Delegation settings for a cgroup subtree.
///
/// Delegation allows a non-root user to manage a cgroup subtree.
#[derive(Debug, Clone, Copy)]
pub struct DelegationConfig {
    /// Whether this cgroup is delegated.
    pub delegated: bool,
    /// UID of the delegate (0 = root).
    pub delegate_uid: u32,
    /// GID of the delegate.
    pub delegate_gid: u32,
    /// Controllers the delegate is allowed to enable.
    pub allowed_controllers: ControllerMask,
}

impl DelegationConfig {
    /// Create a non-delegated configuration.
    pub const fn new() -> Self {
        Self {
            delegated: false,
            delegate_uid: 0,
            delegate_gid: 0,
            allowed_controllers: ControllerMask::empty(),
        }
    }
}

impl Default for DelegationConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ── CgroupNode ────────────────────────────────────────────────────────────────

/// A node in the cgroup v2 hierarchy tree.
///
/// Represents one cgroup with its type, controllers, processes, and
/// links to parent/children.
pub struct CgroupNode {
    /// Cgroup name.
    name: [u8; MAX_NAME_LEN],
    /// Length of the name in bytes.
    name_len: usize,
    /// Cgroup type (domain, threaded, etc.).
    cgroup_type: CgroupType,
    /// Index of parent in the hierarchy (u32::MAX for root).
    parent_idx: u32,
    /// Depth in the hierarchy (root = 0).
    depth: u16,
    /// Child indices.
    children: [u32; MAX_CHILDREN],
    /// Number of children.
    child_count: usize,
    /// Process IDs assigned to this cgroup.
    procs: [u64; MAX_PROCS],
    /// Number of processes.
    proc_count: usize,
    /// Controllers enabled for subtree (`cgroup.subtree_control`).
    subtree_control: ControllerMask,
    /// Controllers available from parent.
    available_controllers: ControllerMask,
    /// CPU controller state.
    cpu: CpuConfig,
    /// Memory controller state.
    memory: MemoryConfig,
    /// I/O controller state.
    io: IoConfig,
    /// PIDs controller state.
    pids: PidsConfig,
    /// Delegation configuration.
    delegation: DelegationConfig,
    /// PSI statistics.
    psi: PsiStats,
    /// Cgroup statistics.
    stat: CgroupStat,
    /// Cgroup events.
    events: CgroupEvents,
    /// Whether this slot is active.
    active: bool,
    /// Whether the cgroup is frozen.
    frozen: bool,
}

impl CgroupNode {
    /// Create an empty (inactive) cgroup node.
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            cgroup_type: CgroupType::Domain,
            parent_idx: u32::MAX,
            depth: 0,
            children: [u32::MAX; MAX_CHILDREN],
            child_count: 0,
            procs: [0u64; MAX_PROCS],
            proc_count: 0,
            subtree_control: ControllerMask::empty(),
            available_controllers: ControllerMask::empty(),
            cpu: CpuConfig::new(),
            memory: MemoryConfig::new(),
            io: IoConfig::new(),
            pids: PidsConfig::new(),
            delegation: DelegationConfig::new(),
            psi: PsiStats::new(),
            stat: CgroupStat::new(),
            events: CgroupEvents::new(),
            active: false,
            frozen: false,
        }
    }

    /// Get the cgroup name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Get the cgroup type.
    pub const fn cgroup_type(&self) -> CgroupType {
        self.cgroup_type
    }

    /// Check if this cgroup is the root.
    pub const fn is_root(&self) -> bool {
        self.parent_idx == u32::MAX
    }

    /// Get the depth in the hierarchy.
    pub const fn depth(&self) -> u16 {
        self.depth
    }

    /// Get the number of children.
    pub const fn child_count(&self) -> usize {
        self.child_count
    }

    /// Get the number of processes.
    pub const fn proc_count(&self) -> usize {
        self.proc_count
    }

    /// Get the subtree_control mask.
    pub const fn subtree_control(&self) -> ControllerMask {
        self.subtree_control
    }

    /// Get the available controllers mask.
    pub const fn available_controllers(&self) -> ControllerMask {
        self.available_controllers
    }

    /// Check if this cgroup is frozen.
    pub const fn is_frozen(&self) -> bool {
        self.frozen
    }

    /// Get reference to CPU config.
    pub const fn cpu(&self) -> &CpuConfig {
        &self.cpu
    }

    /// Get reference to memory config.
    pub const fn memory(&self) -> &MemoryConfig {
        &self.memory
    }

    /// Get reference to I/O config.
    pub const fn io(&self) -> &IoConfig {
        &self.io
    }

    /// Get reference to PIDs config.
    pub const fn pids(&self) -> &PidsConfig {
        &self.pids
    }

    /// Get PSI stats.
    pub const fn psi(&self) -> &PsiStats {
        &self.psi
    }

    /// Get cgroup stat.
    pub const fn stat(&self) -> &CgroupStat {
        &self.stat
    }

    /// Get cgroup events.
    pub const fn events(&self) -> &CgroupEvents {
        &self.events
    }
}

impl Default for CgroupNode {
    fn default() -> Self {
        Self::new()
    }
}

// ── CgroupHierarchy ───────────────────────────────────────────────────────────

/// The cgroup v2 unified hierarchy.
///
/// Manages the tree of cgroups, controller enablement, process
/// assignment, and the no-internal-process constraint.
pub struct CgroupHierarchy {
    /// All cgroup nodes (flat array, tree via parent/child indices).
    nodes: [CgroupNode; MAX_CGROUPS],
    /// Number of active cgroups.
    count: usize,
    /// Root cgroup index (always 0).
    root_idx: usize,
}

impl CgroupHierarchy {
    /// Create a new hierarchy with an initialized root cgroup.
    pub fn new() -> Self {
        let mut hier = Self {
            nodes: [const { CgroupNode::new() }; MAX_CGROUPS],
            count: 0,
            root_idx: 0,
        };
        // Initialize root cgroup.
        hier.nodes[0].active = true;
        hier.nodes[0].name[0] = b'/';
        hier.nodes[0].name_len = 1;
        hier.nodes[0].parent_idx = u32::MAX;
        hier.nodes[0].depth = 0;
        // Root has all controllers available.
        let mut mask = ControllerMask::empty();
        mask = mask.with(ControllerType::Cpu);
        mask = mask.with(ControllerType::Memory);
        mask = mask.with(ControllerType::Io);
        mask = mask.with(ControllerType::Pids);
        mask = mask.with(ControllerType::Cpuset);
        mask = mask.with(ControllerType::Rdma);
        mask = mask.with(ControllerType::Misc);
        hier.nodes[0].available_controllers = mask;
        hier.count = 1;
        hier
    }

    /// Create a child cgroup under the given parent.
    ///
    /// Enforces the no-internal-process constraint: a parent with
    /// processes cannot have children (unless it is the root or
    /// threaded-domain type).
    pub fn create_cgroup(&mut self, parent_idx: usize, name: &[u8]) -> Result<usize> {
        if parent_idx >= self.count || !self.nodes[parent_idx].active {
            return Err(Error::NotFound);
        }
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_CGROUPS {
            return Err(Error::OutOfMemory);
        }

        let parent = &self.nodes[parent_idx];

        // Enforce max depth.
        if parent.depth as usize >= MAX_DEPTH - 1 {
            return Err(Error::InvalidArgument);
        }

        // Enforce max children.
        if parent.child_count >= MAX_CHILDREN {
            return Err(Error::OutOfMemory);
        }

        // No-internal-process constraint: if the parent has processes
        // and is a normal domain, block child creation.
        if parent.proc_count > 0 && parent.cgroup_type == CgroupType::Domain && !parent.is_root() {
            return Err(Error::InvalidArgument);
        }

        // Find free slot.
        let idx = self.find_free_slot()?;
        let new_depth = self.nodes[parent_idx].depth + 1;
        let avail = self.nodes[parent_idx].subtree_control;

        // Initialize the new cgroup.
        let node = &mut self.nodes[idx];
        node.active = true;
        let copy_len = name.len().min(MAX_NAME_LEN);
        node.name[..copy_len].copy_from_slice(&name[..copy_len]);
        node.name_len = copy_len;
        node.cgroup_type = CgroupType::Domain;
        node.parent_idx = parent_idx as u32;
        node.depth = new_depth;
        node.available_controllers = avail;

        // Add child to parent.
        let ccount = self.nodes[parent_idx].child_count;
        self.nodes[parent_idx].children[ccount] = idx as u32;
        self.nodes[parent_idx].child_count = ccount + 1;

        // Update parent stat.
        self.update_descendant_counts(parent_idx);

        if idx >= self.count {
            self.count = idx + 1;
        }

        Ok(idx)
    }

    /// Remove a cgroup (must have no children and no processes).
    pub fn remove_cgroup(&mut self, idx: usize) -> Result<()> {
        if idx == self.root_idx {
            return Err(Error::PermissionDenied);
        }
        if idx >= self.count || !self.nodes[idx].active {
            return Err(Error::NotFound);
        }
        if self.nodes[idx].child_count > 0 {
            return Err(Error::Busy);
        }
        if self.nodes[idx].proc_count > 0 {
            return Err(Error::Busy);
        }

        let parent_idx = self.nodes[idx].parent_idx as usize;

        // Remove from parent's child list.
        let parent = &mut self.nodes[parent_idx];
        let mut found = false;
        for i in 0..parent.child_count {
            if parent.children[i] == idx as u32 {
                // Shift remaining children.
                for j in i..parent.child_count.saturating_sub(1) {
                    parent.children[j] = parent.children[j + 1];
                }
                parent.child_count -= 1;
                found = true;
                break;
            }
        }
        if !found {
            return Err(Error::NotFound);
        }

        self.nodes[idx].active = false;
        self.update_descendant_counts(parent_idx);
        Ok(())
    }

    /// Enable a controller in `cgroup.subtree_control`.
    ///
    /// The controller must be available (inherited from parent) and
    /// the cgroup must not have processes if enabling controllers
    /// (no-internal-process constraint).
    pub fn enable_controller(&mut self, idx: usize, ctrl: ControllerType) -> Result<()> {
        if idx >= self.count || !self.nodes[idx].active {
            return Err(Error::NotFound);
        }
        if !self.nodes[idx].available_controllers.has(ctrl) {
            return Err(Error::InvalidArgument);
        }

        self.nodes[idx].subtree_control = self.nodes[idx].subtree_control.with(ctrl);

        // Propagate to children's available_controllers.
        for i in 0..self.nodes[idx].child_count {
            let child_idx = self.nodes[idx].children[i] as usize;
            self.nodes[child_idx].available_controllers =
                self.nodes[child_idx].available_controllers.with(ctrl);
        }

        Ok(())
    }

    /// Disable a controller in `cgroup.subtree_control`.
    pub fn disable_controller(&mut self, idx: usize, ctrl: ControllerType) -> Result<()> {
        if idx >= self.count || !self.nodes[idx].active {
            return Err(Error::NotFound);
        }

        self.nodes[idx].subtree_control = self.nodes[idx].subtree_control.without(ctrl);

        // Propagate to children.
        for i in 0..self.nodes[idx].child_count {
            let child_idx = self.nodes[idx].children[i] as usize;
            self.nodes[child_idx].available_controllers =
                self.nodes[child_idx].available_controllers.without(ctrl);
        }

        Ok(())
    }

    /// Set cgroup type to threaded.
    ///
    /// The cgroup must be empty (no processes) and its parent becomes
    /// DomainThreaded automatically.
    pub fn set_threaded(&mut self, idx: usize) -> Result<()> {
        if idx == self.root_idx {
            return Err(Error::PermissionDenied);
        }
        if idx >= self.count || !self.nodes[idx].active {
            return Err(Error::NotFound);
        }
        if self.nodes[idx].child_count > 0 {
            return Err(Error::Busy);
        }

        self.nodes[idx].cgroup_type = CgroupType::Threaded;

        // Make parent a threaded domain if it isn't already.
        let parent_idx = self.nodes[idx].parent_idx as usize;
        if self.nodes[parent_idx].cgroup_type == CgroupType::Domain {
            self.nodes[parent_idx].cgroup_type = CgroupType::DomainThreaded;
        }

        Ok(())
    }

    /// Add a process to a cgroup.
    pub fn add_process(&mut self, idx: usize, pid: u64) -> Result<()> {
        if idx >= self.count || !self.nodes[idx].active {
            return Err(Error::NotFound);
        }

        let node = &self.nodes[idx];

        // No-internal-process: can't add processes to a domain
        // cgroup that has children (unless root or threaded-domain).
        if node.child_count > 0 && node.cgroup_type == CgroupType::Domain && !node.is_root() {
            return Err(Error::InvalidArgument);
        }

        // Check PIDs limit.
        if node.pids.is_at_limit() {
            return Err(Error::OutOfMemory);
        }

        if node.proc_count >= MAX_PROCS {
            return Err(Error::OutOfMemory);
        }

        // Check for duplicate.
        for i in 0..node.proc_count {
            if node.procs[i] == pid {
                return Err(Error::AlreadyExists);
            }
        }

        let pc = self.nodes[idx].proc_count;
        self.nodes[idx].procs[pc] = pid;
        self.nodes[idx].proc_count = pc + 1;
        self.nodes[idx].pids.current += 1;
        self.nodes[idx].events.populated = true;

        Ok(())
    }

    /// Remove a process from a cgroup.
    pub fn remove_process(&mut self, idx: usize, pid: u64) -> Result<()> {
        if idx >= self.count || !self.nodes[idx].active {
            return Err(Error::NotFound);
        }

        let node = &mut self.nodes[idx];
        let mut found = false;
        for i in 0..node.proc_count {
            if node.procs[i] == pid {
                for j in i..node.proc_count.saturating_sub(1) {
                    node.procs[j] = node.procs[j + 1];
                }
                node.proc_count -= 1;
                node.pids.current = node.pids.current.saturating_sub(1);
                found = true;
                break;
            }
        }

        if !found {
            return Err(Error::NotFound);
        }

        if node.proc_count == 0 {
            node.events.populated = false;
        }

        Ok(())
    }

    /// Freeze or thaw a cgroup.
    pub fn set_frozen(&mut self, idx: usize, frozen: bool) -> Result<()> {
        if idx >= self.count || !self.nodes[idx].active {
            return Err(Error::NotFound);
        }
        self.nodes[idx].frozen = frozen;
        self.nodes[idx].events.frozen = frozen;
        Ok(())
    }

    /// Configure CPU controller for a cgroup.
    pub fn set_cpu_config(&mut self, idx: usize, config: CpuConfig) -> Result<()> {
        if idx >= self.count || !self.nodes[idx].active {
            return Err(Error::NotFound);
        }
        if !self.nodes[idx]
            .available_controllers
            .has(ControllerType::Cpu)
        {
            return Err(Error::InvalidArgument);
        }
        self.nodes[idx].cpu = config;
        Ok(())
    }

    /// Configure memory controller for a cgroup.
    pub fn set_memory_config(&mut self, idx: usize, config: MemoryConfig) -> Result<()> {
        if idx >= self.count || !self.nodes[idx].active {
            return Err(Error::NotFound);
        }
        if !self.nodes[idx]
            .available_controllers
            .has(ControllerType::Memory)
        {
            return Err(Error::InvalidArgument);
        }
        self.nodes[idx].memory = config;
        Ok(())
    }

    /// Configure I/O controller for a cgroup.
    pub fn set_io_config(&mut self, idx: usize, config: IoConfig) -> Result<()> {
        if idx >= self.count || !self.nodes[idx].active {
            return Err(Error::NotFound);
        }
        if !self.nodes[idx]
            .available_controllers
            .has(ControllerType::Io)
        {
            return Err(Error::InvalidArgument);
        }
        self.nodes[idx].io = config;
        Ok(())
    }

    /// Configure PIDs controller for a cgroup.
    pub fn set_pids_max(&mut self, idx: usize, max: u32) -> Result<()> {
        if idx >= self.count || !self.nodes[idx].active {
            return Err(Error::NotFound);
        }
        if !self.nodes[idx]
            .available_controllers
            .has(ControllerType::Pids)
        {
            return Err(Error::InvalidArgument);
        }
        self.nodes[idx].pids.max = max;
        Ok(())
    }

    /// Set delegation for a cgroup.
    pub fn set_delegation(&mut self, idx: usize, config: DelegationConfig) -> Result<()> {
        if idx >= self.count || !self.nodes[idx].active {
            return Err(Error::NotFound);
        }
        self.nodes[idx].delegation = config;
        Ok(())
    }

    /// Record a PSI stall event.
    pub fn record_psi(&mut self, idx: usize, some_us: u64, full_us: u64) -> Result<()> {
        if idx >= self.count || !self.nodes[idx].active {
            return Err(Error::NotFound);
        }
        self.nodes[idx]
            .psi
            .record_stall(some_us, full_us, PSI_WINDOW_US);
        Ok(())
    }

    /// Get a reference to a cgroup node.
    pub fn get(&self, idx: usize) -> Result<&CgroupNode> {
        if idx >= self.count || !self.nodes[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&self.nodes[idx])
    }

    /// Get a mutable reference to a cgroup node.
    pub fn get_mut(&mut self, idx: usize) -> Result<&mut CgroupNode> {
        if idx >= self.count || !self.nodes[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&mut self.nodes[idx])
    }

    /// Get the root cgroup index.
    pub const fn root_idx(&self) -> usize {
        self.root_idx
    }

    /// Get the number of active cgroups.
    pub fn active_count(&self) -> usize {
        let mut n = 0;
        for i in 0..self.count {
            if self.nodes[i].active {
                n += 1;
            }
        }
        n
    }

    /// List controllers available at a given cgroup.
    pub fn list_controllers(&self, idx: usize) -> Result<ControllerMask> {
        if idx >= self.count || !self.nodes[idx].active {
            return Err(Error::NotFound);
        }
        Ok(self.nodes[idx].available_controllers)
    }

    /// List controllers enabled in subtree_control.
    pub fn list_subtree_control(&self, idx: usize) -> Result<ControllerMask> {
        if idx >= self.count || !self.nodes[idx].active {
            return Err(Error::NotFound);
        }
        Ok(self.nodes[idx].subtree_control)
    }

    /// Find a free slot in the nodes array.
    fn find_free_slot(&self) -> Result<usize> {
        for i in 0..self.count {
            if !self.nodes[i].active {
                return Ok(i);
            }
        }
        if self.count < MAX_CGROUPS {
            return Ok(self.count);
        }
        Err(Error::OutOfMemory)
    }

    /// Recursively update descendant counts for a cgroup and
    /// its ancestors.
    fn update_descendant_counts(&mut self, idx: usize) {
        let count = self.count_descendants(idx);
        self.nodes[idx].stat.nr_descendants = count;

        // Walk up to root.
        let mut current = self.nodes[idx].parent_idx;
        while current != u32::MAX {
            let ci = current as usize;
            let c = self.count_descendants(ci);
            self.nodes[ci].stat.nr_descendants = c;
            current = self.nodes[ci].parent_idx;
        }
    }

    /// Count active descendants of a cgroup.
    fn count_descendants(&self, idx: usize) -> u32 {
        let mut total = 0u32;
        for i in 0..self.nodes[idx].child_count {
            let child_idx = self.nodes[idx].children[i] as usize;
            if self.nodes[child_idx].active {
                total += 1;
                total += self.count_descendants(child_idx);
            }
        }
        total
    }
}

impl Default for CgroupHierarchy {
    fn default() -> Self {
        Self::new()
    }
}
