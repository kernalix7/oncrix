// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cgroup v2 core hierarchy management.
//!
//! Implements the cgroup v2 unified hierarchy, including cgroup creation,
//! deletion, task attachment, controller enablement, and the core lifecycle
//! management. This module provides the foundational infrastructure that all
//! individual cgroup controllers (cpu, memory, io, pids) build upon.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use oncrix_lib::{Error, Result};

/// Maximum depth of the cgroup hierarchy.
pub const CGROUP_MAX_DEPTH: usize = 32;

/// Maximum number of cgroups in the system.
pub const CGROUP_MAX_COUNT: usize = 65536;

/// Maximum length of a cgroup name.
pub const CGROUP_NAME_MAX: usize = 64;

/// Controller flags indicating which controllers are available/enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Controller {
    /// CPU bandwidth controller.
    Cpu = 1 << 0,
    /// Memory controller.
    Memory = 1 << 1,
    /// I/O controller.
    Io = 1 << 2,
    /// PIDs controller.
    Pids = 1 << 3,
    /// CPU set controller.
    Cpuset = 1 << 4,
    /// Hugetlb controller.
    Hugetlb = 1 << 5,
    /// RDMA controller.
    Rdma = 1 << 6,
    /// Miscellaneous controller.
    Misc = 1 << 7,
}

/// State of a cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupState {
    /// Cgroup is alive and operational.
    Online,
    /// Cgroup is being destroyed (no new tasks may join).
    Dying,
    /// Cgroup has been fully removed.
    Dead,
}

/// Unique identifier for a cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CgroupId(u64);

impl CgroupId {
    /// Creates a new cgroup ID from a raw value.
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Returns the raw u64 value.
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

/// Controller subsystem state attached to a cgroup.
pub struct CgroupSubsysState {
    /// Reference count for this subsystem state.
    refcount: AtomicU32,
    /// The cgroup this state belongs to.
    cgroup_id: CgroupId,
    /// Flags specific to this subsystem state.
    flags: u32,
}

impl CgroupSubsysState {
    /// Creates a new subsystem state for the given cgroup.
    pub const fn new(cgroup_id: CgroupId) -> Self {
        Self {
            refcount: AtomicU32::new(1),
            cgroup_id,
            flags: 0,
        }
    }

    /// Increments the reference count.
    pub fn get(&self) {
        self.refcount.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrements the reference count, returning true if it reached zero.
    pub fn put(&self) -> bool {
        self.refcount.fetch_sub(1, Ordering::AcqRel) == 1
    }

    /// Returns the cgroup ID this state belongs to.
    pub fn cgroup_id(&self) -> CgroupId {
        self.cgroup_id
    }
}

impl Default for CgroupSubsysState {
    fn default() -> Self {
        Self::new(CgroupId::new(0))
    }
}

/// Core cgroup structure representing a single control group.
pub struct Cgroup {
    /// Unique identifier for this cgroup.
    id: CgroupId,
    /// Human-readable name.
    name: [u8; CGROUP_NAME_MAX],
    /// Current state of this cgroup.
    state: CgroupState,
    /// Bitmask of enabled controllers.
    enabled_controllers: u32,
    /// Bitmask of controllers available (subset of parent's enabled).
    available_controllers: u32,
    /// Depth in the cgroup hierarchy (root = 0).
    depth: u32,
    /// Number of tasks currently in this cgroup.
    task_count: AtomicU32,
    /// Number of live children.
    child_count: AtomicU32,
    /// Serial number for ordering events.
    serial_nr: u64,
}

impl Cgroup {
    /// Creates the root cgroup.
    pub const fn new_root() -> Self {
        Self {
            id: CgroupId::new(1),
            name: [0u8; CGROUP_NAME_MAX],
            state: CgroupState::Online,
            enabled_controllers: 0,
            available_controllers: 0,
            depth: 0,
            task_count: AtomicU32::new(0),
            child_count: AtomicU32::new(0),
            serial_nr: 1,
        }
    }

    /// Creates a new cgroup with the given ID, name, and depth.
    pub fn new(id: CgroupId, name: &[u8], depth: u32) -> Result<Self> {
        if depth as usize >= CGROUP_MAX_DEPTH {
            return Err(Error::InvalidArgument);
        }
        if name.len() > CGROUP_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        let mut cg = Self {
            id,
            name: [0u8; CGROUP_NAME_MAX],
            state: CgroupState::Online,
            enabled_controllers: 0,
            available_controllers: 0,
            depth,
            task_count: AtomicU32::new(0),
            child_count: AtomicU32::new(0),
            serial_nr: id.as_u64(),
        };
        cg.name[..name.len()].copy_from_slice(name);
        Ok(cg)
    }

    /// Returns this cgroup's ID.
    pub fn id(&self) -> CgroupId {
        self.id
    }

    /// Returns the current state of this cgroup.
    pub fn state(&self) -> CgroupState {
        self.state
    }

    /// Returns true if the cgroup is online (not dying or dead).
    pub fn is_online(&self) -> bool {
        self.state == CgroupState::Online
    }

    /// Returns the depth in the hierarchy.
    pub fn depth(&self) -> u32 {
        self.depth
    }

    /// Returns the number of tasks in this cgroup.
    pub fn task_count(&self) -> u32 {
        self.task_count.load(Ordering::Relaxed)
    }

    /// Returns the number of child cgroups.
    pub fn child_count(&self) -> u32 {
        self.child_count.load(Ordering::Relaxed)
    }

    /// Returns the enabled controller bitmask.
    pub fn enabled_controllers(&self) -> u32 {
        self.enabled_controllers
    }

    /// Returns the available controller bitmask.
    pub fn available_controllers(&self) -> u32 {
        self.available_controllers
    }

    /// Checks if a specific controller is enabled in this cgroup.
    pub fn controller_enabled(&self, ctrl: Controller) -> bool {
        self.enabled_controllers & (ctrl as u32) != 0
    }

    /// Enables a controller on this cgroup.
    ///
    /// The controller must be in the available set (propagated from parent).
    pub fn enable_controller(&mut self, ctrl: Controller) -> Result<()> {
        let mask = ctrl as u32;
        if self.available_controllers & mask == 0 {
            return Err(Error::PermissionDenied);
        }
        // Cannot enable controllers on a cgroup that has tasks.
        if self.task_count.load(Ordering::Acquire) > 0 {
            return Err(Error::Busy);
        }
        self.enabled_controllers |= mask;
        Ok(())
    }

    /// Disables a controller on this cgroup.
    pub fn disable_controller(&mut self, ctrl: Controller) -> Result<()> {
        // Cannot disable if children have it enabled.
        if self.child_count.load(Ordering::Acquire) > 0 {
            return Err(Error::Busy);
        }
        self.enabled_controllers &= !(ctrl as u32);
        Ok(())
    }

    /// Marks this cgroup as dying (beginning of destruction).
    pub fn begin_destroy(&mut self) {
        self.state = CgroupState::Dying;
    }

    /// Marks this cgroup as fully dead.
    pub fn finish_destroy(&mut self) {
        self.state = CgroupState::Dead;
    }

    /// Records a task joining this cgroup.
    pub fn attach_task(&self) {
        self.task_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a task leaving this cgroup.
    pub fn detach_task(&self) {
        self.task_count.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Default for Cgroup {
    fn default() -> Self {
        Self::new_root()
    }
}

/// Global cgroup ID allocator.
static NEXT_CGROUP_ID: AtomicU64 = AtomicU64::new(2);

/// Allocates a new unique cgroup ID.
pub fn alloc_cgroup_id() -> Result<CgroupId> {
    let id = NEXT_CGROUP_ID.fetch_add(1, Ordering::Relaxed);
    if id as usize > CGROUP_MAX_COUNT {
        return Err(Error::OutOfMemory);
    }
    Ok(CgroupId::new(id))
}

/// Cgroup hierarchy descriptor.
///
/// Represents the entire cgroup v2 unified hierarchy, holding the root
/// cgroup and global configuration state.
pub struct CgroupRoot {
    /// The root cgroup of this hierarchy.
    root_cgroup: Cgroup,
    /// Bitmask of controllers registered with this hierarchy.
    registered_controllers: u32,
    /// Total number of cgroups currently alive.
    cgroup_count: AtomicU32,
    /// Whether the hierarchy has been fully initialized.
    initialized: bool,
}

impl CgroupRoot {
    /// Creates a new, uninitialized cgroup root hierarchy.
    pub const fn new() -> Self {
        Self {
            root_cgroup: Cgroup::new_root(),
            registered_controllers: 0,
            cgroup_count: AtomicU32::new(1),
            initialized: false,
        }
    }

    /// Initializes the cgroup root hierarchy.
    ///
    /// Must be called once during system startup before any cgroups are created.
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }
        // Make all controllers available at root.
        self.root_cgroup.available_controllers = u32::MAX;
        self.initialized = true;
        Ok(())
    }

    /// Returns a reference to the root cgroup.
    pub fn root(&self) -> &Cgroup {
        &self.root_cgroup
    }

    /// Returns the total count of live cgroups.
    pub fn cgroup_count(&self) -> u32 {
        self.cgroup_count.load(Ordering::Relaxed)
    }

    /// Registers a controller with the hierarchy.
    pub fn register_controller(&mut self, ctrl: Controller) {
        self.registered_controllers |= ctrl as u32;
        self.root_cgroup.available_controllers |= ctrl as u32;
    }

    /// Returns true if the hierarchy is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Called when a new cgroup is created under this hierarchy.
    pub fn on_cgroup_create(&self) -> Result<()> {
        let count = self.cgroup_count.fetch_add(1, Ordering::Relaxed);
        if count as usize >= CGROUP_MAX_COUNT {
            self.cgroup_count.fetch_sub(1, Ordering::Relaxed);
            return Err(Error::OutOfMemory);
        }
        Ok(())
    }

    /// Called when a cgroup is destroyed.
    pub fn on_cgroup_destroy(&self) {
        self.cgroup_count.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Default for CgroupRoot {
    fn default() -> Self {
        Self::new()
    }
}

/// Task migration descriptor used when moving tasks between cgroups.
pub struct CgroupMigration {
    /// ID of the source cgroup.
    pub src_id: CgroupId,
    /// ID of the destination cgroup.
    pub dst_id: CgroupId,
    /// The task (PID) being migrated.
    pub pid: u64,
    /// Controllers that need to handle this migration.
    pub controller_mask: u32,
}

impl CgroupMigration {
    /// Creates a new migration descriptor.
    pub fn new(src_id: CgroupId, dst_id: CgroupId, pid: u64, controller_mask: u32) -> Self {
        Self {
            src_id,
            dst_id,
            pid,
            controller_mask,
        }
    }
}

/// Validates that a cgroup name is well-formed.
///
/// Cgroup names must be non-empty, no longer than `CGROUP_NAME_MAX`,
/// and consist only of alphanumeric characters, `-`, `_`, or `.`.
pub fn validate_cgroup_name(name: &[u8]) -> Result<()> {
    if name.is_empty() || name.len() > CGROUP_NAME_MAX {
        return Err(Error::InvalidArgument);
    }
    for &b in name {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' => {}
            _ => return Err(Error::InvalidArgument),
        }
    }
    Ok(())
}

/// Controller operations trait that all cgroup controllers must implement.
pub trait CgroupController {
    /// Called when a new cgroup is created.
    fn css_alloc(&self, cgroup: &Cgroup) -> Result<CgroupSubsysState>;

    /// Called when a task is attached to a cgroup.
    fn attach(&self, migration: &CgroupMigration) -> Result<()>;

    /// Called when a cgroup is about to be destroyed.
    fn css_offline(&self, state: &CgroupSubsysState);

    /// Called when a cgroup has been fully destroyed.
    fn css_free(&self, state: CgroupSubsysState);

    /// Returns the name identifier of this controller.
    fn name(&self) -> &'static str;
}

/// Events that can occur on a cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupEvent {
    /// A task was added to the cgroup.
    TaskAttach { pid: u64 },
    /// A task was removed from the cgroup.
    TaskDetach { pid: u64 },
    /// The cgroup became empty (no tasks, no children).
    BecameEmpty,
    /// A controller was enabled.
    ControllerEnabled { controller: Controller },
    /// A controller was disabled.
    ControllerDisabled { controller: Controller },
}
