// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cgroup v2 filesystem.
//!
//! Implements the cgroupfs VFS layer for cgroup v2. The cgroup hierarchy is
//! mounted at a single root and exposes a directory tree where each cgroup
//! directory contains standard interface files (cgroup.procs, cgroup.controllers,
//! cgroup.subtree_control, etc.).

use oncrix_lib::{Error, Result};

/// Maximum number of cgroups in the system.
pub const CGROUP_MAX: usize = 256;

/// Maximum cgroup name length.
pub const CGROUP_NAME_MAX: usize = 64;

/// Maximum depth of the cgroup hierarchy.
pub const CGROUP_MAX_DEPTH: usize = 16;

/// Standard cgroup v2 interface file names.
pub const CGROUP_PROCS: &str = "cgroup.procs";
pub const CGROUP_CONTROLLERS: &str = "cgroup.controllers";
pub const CGROUP_SUBTREE_CONTROL: &str = "cgroup.subtree_control";
pub const CGROUP_EVENTS: &str = "cgroup.events";
pub const CGROUP_MAX_DESCENDANTS: &str = "cgroup.max.descendants";
pub const CGROUP_MAX_DEPTH_FILE: &str = "cgroup.max.depth";
pub const CGROUP_STAT: &str = "cgroup.stat";
pub const CGROUP_FREEZE: &str = "cgroup.freeze";
pub const CGROUP_KILL: &str = "cgroup.kill";
pub const CGROUP_TYPE: &str = "cgroup.type";

/// Available cgroup controllers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CgroupController {
    /// CPU bandwidth and scheduling.
    Cpu = 1 << 0,
    /// CPU set affinity.
    CpuSet = 1 << 1,
    /// Memory usage limits.
    Memory = 1 << 2,
    /// Block I/O throttling.
    Io = 1 << 3,
    /// PID count limits.
    Pids = 1 << 4,
    /// RDMA device limits.
    Rdma = 1 << 5,
    /// HugeTLB usage.
    HugeTlb = 1 << 6,
    /// Perf events.
    Perf = 1 << 7,
    /// Network priority.
    Net = 1 << 8,
}

/// Bitmask of controllers.
pub type ControllerMask = u32;

/// Cgroup state flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupState {
    /// Normal operational state.
    Running,
    /// Frozen (processes paused).
    Frozen,
    /// Being deleted.
    Dying,
}

/// A single cgroup node.
#[derive(Debug)]
pub struct CgroupNode {
    /// Cgroup ID (internal handle).
    pub id: u32,
    /// Parent cgroup ID (u32::MAX for root).
    pub parent_id: u32,
    /// Name of this cgroup.
    pub name: [u8; CGROUP_NAME_MAX],
    /// Name length.
    pub name_len: usize,
    /// Controllers enabled on this cgroup.
    pub controllers: ControllerMask,
    /// Controllers requested for subtree delegation.
    pub subtree_control: ControllerMask,
    /// Current state.
    pub state: CgroupState,
    /// Whether this is a threaded cgroup.
    pub threaded: bool,
    /// Number of direct child cgroups.
    pub child_count: u32,
    /// Number of processes directly in this cgroup.
    pub nr_procs: u32,
    /// Maximum number of descendant cgroups (u32::MAX = unlimited).
    pub max_descendants: u32,
    /// Maximum hierarchy depth below this cgroup.
    pub max_depth: u32,
    /// Depth of this cgroup in the hierarchy (root = 0).
    pub depth: u32,
}

impl CgroupNode {
    /// Create a new cgroup node.
    pub const fn new(id: u32, parent_id: u32, depth: u32) -> Self {
        Self {
            id,
            parent_id,
            name: [0u8; CGROUP_NAME_MAX],
            name_len: 0,
            controllers: 0,
            subtree_control: 0,
            state: CgroupState::Running,
            threaded: false,
            child_count: 0,
            nr_procs: 0,
            max_descendants: u32::MAX,
            max_depth: u32::MAX,
            depth,
        }
    }

    /// Set the cgroup name from a byte slice.
    pub fn set_name(&mut self, name: &[u8]) -> Result<()> {
        if name.is_empty() || name.len() >= CGROUP_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        // Validate: no '/' or null bytes.
        for &b in name {
            if b == b'/' || b == 0 {
                return Err(Error::InvalidArgument);
            }
        }
        self.name[..name.len()].copy_from_slice(name);
        self.name_len = name.len();
        Ok(())
    }

    /// Return the name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Enable a controller on this cgroup.
    pub fn enable_controller(&mut self, ctrl: CgroupController) -> Result<()> {
        self.controllers |= ctrl as u32;
        Ok(())
    }

    /// Set the subtree_control mask.
    ///
    /// Only controllers that are enabled on this cgroup can be delegated.
    pub fn set_subtree_control(&mut self, mask: ControllerMask) -> Result<()> {
        if mask & !self.controllers != 0 {
            return Err(Error::InvalidArgument);
        }
        // Cannot enable subtree_control if there are tasks in this cgroup.
        if self.nr_procs > 0 {
            return Err(Error::Busy);
        }
        self.subtree_control = mask;
        Ok(())
    }

    /// Return true if the cgroup is in a frozen state.
    pub fn is_frozen(&self) -> bool {
        self.state == CgroupState::Frozen
    }

    /// Return true if the cgroup is the root.
    pub fn is_root(&self) -> bool {
        self.parent_id == u32::MAX
    }
}

/// The cgroup filesystem hierarchy.
#[derive(Debug)]
pub struct CgroupFs {
    /// All cgroup nodes indexed by (id % CGROUP_MAX).
    nodes: [Option<CgroupNode>; CGROUP_MAX],
    /// Next cgroup ID to assign.
    next_id: u32,
    /// Mounted (true after cgroupfs is mounted).
    pub mounted: bool,
}

impl CgroupFs {
    /// Create a new cgroupfs, pre-populating the root cgroup.
    pub fn new() -> Self {
        let mut fs = Self {
            nodes: [const { None }; CGROUP_MAX],
            next_id: 1,
            mounted: false,
        };
        // Create root cgroup (id=1, parent=MAX).
        let mut root = CgroupNode::new(1, u32::MAX, 0);
        let _ = root.set_name(b"/");
        fs.nodes[0] = Some(root);
        fs.next_id = 2;
        fs
    }

    fn alloc_id(&mut self) -> Result<u32> {
        let id = self.next_id;
        self.next_id = id.checked_add(1).ok_or(Error::OutOfMemory)?;
        Ok(id)
    }

    fn find_slot(&self) -> Option<usize> {
        self.nodes.iter().position(|n| n.is_none())
    }

    fn find_by_id(&self, id: u32) -> Option<usize> {
        self.nodes
            .iter()
            .position(|n| n.as_ref().map_or(false, |cg| cg.id == id))
    }

    /// Mount the cgroupfs.
    pub fn mount(&mut self) -> Result<()> {
        if self.mounted {
            return Err(Error::AlreadyExists);
        }
        self.mounted = true;
        Ok(())
    }

    /// Create a child cgroup under `parent_id` with the given name.
    ///
    /// Returns the new cgroup's ID.
    pub fn mkdir(&mut self, parent_id: u32, name: &[u8]) -> Result<u32> {
        if !self.mounted {
            return Err(Error::IoError);
        }
        let parent_idx = self.find_by_id(parent_id).ok_or(Error::NotFound)?;

        let parent_depth = self.nodes[parent_idx].as_ref().unwrap().depth;
        if parent_depth as usize >= CGROUP_MAX_DEPTH {
            return Err(Error::InvalidArgument);
        }

        // Check parent's max_depth constraint.
        let parent_max_depth = self.nodes[parent_idx].as_ref().unwrap().max_depth;
        if parent_max_depth == 0 {
            return Err(Error::PermissionDenied);
        }

        let parent_subtree_ctrl = self.nodes[parent_idx].as_ref().unwrap().subtree_control;

        let slot = self.find_slot().ok_or(Error::OutOfMemory)?;
        let new_id = self.alloc_id()?;
        let mut cg = CgroupNode::new(new_id, parent_id, parent_depth + 1);
        cg.set_name(name)?;
        cg.controllers = parent_subtree_ctrl;

        if let Some(parent) = self.nodes[parent_idx].as_mut() {
            parent.child_count += 1;
        }

        self.nodes[slot] = Some(cg);
        Ok(new_id)
    }

    /// Remove an empty cgroup.
    pub fn rmdir(&mut self, id: u32) -> Result<()> {
        if id == 1 {
            return Err(Error::PermissionDenied); // Cannot remove root.
        }
        let idx = self.find_by_id(id).ok_or(Error::NotFound)?;
        let cg = self.nodes[idx].as_ref().unwrap();
        if cg.child_count > 0 {
            return Err(Error::Busy);
        }
        if cg.nr_procs > 0 {
            return Err(Error::Busy);
        }
        let parent_id = cg.parent_id;
        self.nodes[idx] = None;

        if let Some(parent_idx) = self.find_by_id(parent_id) {
            if let Some(parent) = self.nodes[parent_idx].as_mut() {
                parent.child_count = parent.child_count.saturating_sub(1);
            }
        }
        Ok(())
    }

    /// Attach a process to a cgroup.
    pub fn attach_proc(&mut self, cg_id: u32) -> Result<()> {
        let idx = self.find_by_id(cg_id).ok_or(Error::NotFound)?;
        let cg = self.nodes[idx].as_mut().unwrap();
        if cg.state == CgroupState::Dying {
            return Err(Error::NotFound);
        }
        // Cannot write procs to an internal node with subtree_control set.
        if cg.subtree_control != 0 && cg.child_count > 0 {
            return Err(Error::InvalidArgument);
        }
        cg.nr_procs += 1;
        Ok(())
    }

    /// Remove a process from a cgroup.
    pub fn detach_proc(&mut self, cg_id: u32) -> Result<()> {
        let idx = self.find_by_id(cg_id).ok_or(Error::NotFound)?;
        let cg = self.nodes[idx].as_mut().unwrap();
        cg.nr_procs = cg.nr_procs.saturating_sub(1);
        Ok(())
    }

    /// Get a reference to a cgroup by ID.
    pub fn get(&self, id: u32) -> Option<&CgroupNode> {
        let idx = self.find_by_id(id)?;
        self.nodes[idx].as_ref()
    }

    /// Get a mutable reference to a cgroup by ID.
    pub fn get_mut(&mut self, id: u32) -> Option<&mut CgroupNode> {
        let idx = self.find_by_id(id)?;
        self.nodes[idx].as_mut()
    }

    /// Freeze a cgroup and all its descendants.
    pub fn freeze(&mut self, id: u32) -> Result<()> {
        let idx = self.find_by_id(id).ok_or(Error::NotFound)?;
        let cg = self.nodes[idx].as_mut().unwrap();
        cg.state = CgroupState::Frozen;
        Ok(())
    }

    /// Thaw a frozen cgroup.
    pub fn thaw(&mut self, id: u32) -> Result<()> {
        let idx = self.find_by_id(id).ok_or(Error::NotFound)?;
        let cg = self.nodes[idx].as_mut().unwrap();
        if cg.state == CgroupState::Frozen {
            cg.state = CgroupState::Running;
        }
        Ok(())
    }

    /// Write to cgroup.subtree_control interface file.
    pub fn write_subtree_control(&mut self, id: u32, mask: ControllerMask) -> Result<()> {
        let idx = self.find_by_id(id).ok_or(Error::NotFound)?;
        let cg = self.nodes[idx].as_mut().unwrap();
        cg.set_subtree_control(mask)
    }
}

impl Default for CgroupFs {
    fn default() -> Self {
        Self::new()
    }
}

/// Format the cgroup.controllers file content.
pub fn format_controllers(mask: ControllerMask, buf: &mut [u8]) -> usize {
    let names: &[(&str, u32)] = &[
        ("cpu", CgroupController::Cpu as u32),
        ("cpuset", CgroupController::CpuSet as u32),
        ("memory", CgroupController::Memory as u32),
        ("io", CgroupController::Io as u32),
        ("pids", CgroupController::Pids as u32),
        ("rdma", CgroupController::Rdma as u32),
        ("hugetlb", CgroupController::HugeTlb as u32),
        ("perf_event", CgroupController::Perf as u32),
        ("net_cls", CgroupController::Net as u32),
    ];

    let mut pos = 0usize;
    let mut first = true;
    for (name, bit) in names {
        if mask & bit != 0 {
            if !first && pos < buf.len() {
                buf[pos] = b' ';
                pos += 1;
            }
            let bytes = name.as_bytes();
            let copy_len = bytes.len().min(buf.len().saturating_sub(pos));
            buf[pos..pos + copy_len].copy_from_slice(&bytes[..copy_len]);
            pos += copy_len;
            first = false;
        }
    }
    if pos < buf.len() {
        buf[pos] = b'\n';
        pos += 1;
    }
    pos
}
