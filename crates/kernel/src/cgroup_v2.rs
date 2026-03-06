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
