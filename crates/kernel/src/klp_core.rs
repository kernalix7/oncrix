// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel livepatch core: unified lifecycle management.
//!
//! Provides a higher-level interface over the registration layer in
//! [`super::livepatch`] and the apply/revert engine in
//! [`super::klp_apply`]. This module owns:
//!
//! - Patch object lifecycle (load, enable, disable, unload).
//! - Per-task consistency model with universe tracking.
//! - Transition state machine driving the apply/revert flow.
//! - Sysfs-like status interface for patch introspection.
//!
//! # Consistency model
//!
//! Each task operates in one of two "universes":
//! - **Unpatched**: executing original function code.
//! - **Patched**: executing replacement function code.
//!
//! A transition moves all tasks from one universe to the other.
//! Tasks switch universes at safe transition points (system calls,
//! voluntary schedule). A force timeout moves remaining tasks
//! involuntarily.
//!
//! # State machine
//!
//! ```text
//! Loaded ─ enable ─> Enabling ─ (all tasks migrated) ─> Enabled
//!   ^                    │                                  │
//!   │                (force)                             disable
//!   │                    ↓                                  │
//!   └── unload ── Disabled <── Disabling <──────────────────┘
//! ```
//!
//! # Types
//!
//! - [`KlpObjectState`] -- lifecycle state of a patch object
//! - [`KlpUniverse`] -- per-task consistency universe
//! - [`KlpTaskState`] -- per-task transition tracking
//! - [`KlpFuncDesc`] -- function replacement descriptor
//! - [`KlpObject`] -- a patch object with function replacements
//! - [`KlpTransitionKind`] -- whether we are enabling or disabling
//! - [`KlpTransitionEngine`] -- drives the transition state machine
//! - [`KlpPatchStatus`] -- sysfs-like status for external queries
//! - [`KlpCore`] -- top-level livepatch manager
//!
//! Reference: Linux `kernel/livepatch/core.c`,
//! `kernel/livepatch/transition.c`.

#[allow(dead_code)]
use oncrix_lib::{Error, Result};

// -- Constants ---------------------------------------------------------------

/// Maximum function replacements per patch object.
const MAX_FUNCS: usize = 32;

/// Maximum patch objects managed by [`KlpCore`].
const MAX_OBJECTS: usize = 16;

/// Maximum tasks tracked for consistency transitions.
const MAX_TASKS: usize = 256;

/// Maximum name length in bytes.
const MAX_NAME_LEN: usize = 64;

/// Default force-transition timeout in ticks.
const DEFAULT_FORCE_TIMEOUT: u64 = 2000;

/// Maximum sysfs-like status entries.
const MAX_STATUS_ENTRIES: usize = 16;

// -- KlpObjectState ----------------------------------------------------------

/// Lifecycle state of a patch object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KlpObjectState {
    /// Object is loaded but not active.
    #[default]
    Loaded,
    /// Transition to enabled is in progress.
    Enabling,
    /// Object is fully active (all tasks patched).
    Enabled,
    /// Transition to disabled is in progress.
    Disabling,
    /// Object has been disabled.
    Disabled,
}

// -- KlpUniverse -------------------------------------------------------------

/// Per-task consistency universe.
///
/// Tracks which version of the code a task is currently executing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KlpUniverse {
    /// Task is executing original (unpatched) code.
    #[default]
    Unpatched,
    /// Task is executing replacement (patched) code.
    Patched,
}

// -- KlpTaskState ------------------------------------------------------------

/// Per-task transition tracking.
///
/// Records which universe the task is in and whether it has reached
/// a safe transition point.
#[derive(Clone, Copy)]
pub struct KlpTaskState {
    /// Task identifier.
    task_id: u64,
    /// Current universe.
    universe: KlpUniverse,
    /// Whether the task has reached a safe transition point.
    at_safe_point: bool,
    /// Whether this entry is in use.
    occupied: bool,
}

impl KlpTaskState {
    /// Create an empty entry.
    const fn empty() -> Self {
        Self {
            task_id: 0,
            universe: KlpUniverse::Unpatched,
            at_safe_point: false,
            occupied: false,
        }
    }

    /// Return the task ID.
    pub const fn task_id(&self) -> u64 {
        self.task_id
    }

    /// Return the current universe.
    pub const fn universe(&self) -> KlpUniverse {
        self.universe
    }

    /// Return whether the task is at a safe transition point.
    pub const fn at_safe_point(&self) -> bool {
        self.at_safe_point
    }
}

impl Default for KlpTaskState {
    fn default() -> Self {
        Self::empty()
    }
}

// -- KlpFuncDesc -------------------------------------------------------------

/// Function replacement descriptor.
///
/// Describes a single function to be patched: the original address,
/// the replacement address, and a name for diagnostics.
#[derive(Clone, Copy)]
pub struct KlpFuncDesc {
    /// Address of the original function.
    pub original_addr: u64,
    /// Address of the replacement function.
    pub new_addr: u64,
    /// Function name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Whether this slot is in use.
    active: bool,
    /// Whether the redirect is currently live.
    redirecting: bool,
}

impl KlpFuncDesc {
    /// Create an empty (inactive) function descriptor.
    const fn empty() -> Self {
        Self {
            original_addr: 0,
            new_addr: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            active: false,
            redirecting: false,
        }
    }

    /// Create a new function descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `name` is empty or too
    /// long, or if either address is zero.
    pub fn new(original_addr: u64, new_addr: u64, name: &[u8]) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if original_addr == 0 || new_addr == 0 {
            return Err(Error::InvalidArgument);
        }
        let mut desc = Self::empty();
        desc.original_addr = original_addr;
        desc.new_addr = new_addr;
        desc.name[..name.len()].copy_from_slice(name);
        desc.name_len = name.len();
        desc.active = true;
        Ok(desc)
    }

    /// Return the function name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return whether this descriptor is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Return whether the redirect is live.
    pub const fn is_redirecting(&self) -> bool {
        self.redirecting
    }
}

impl Default for KlpFuncDesc {
    fn default() -> Self {
        Self::empty()
    }
}

// -- KlpObject ---------------------------------------------------------------

/// A patch object containing function replacements and lifecycle
/// state.
///
/// Manages up to [`MAX_FUNCS`] function descriptors and tracks the
/// object through its lifecycle states.
pub struct KlpObject {
    /// Object name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Function replacements.
    funcs: [KlpFuncDesc; MAX_FUNCS],
    /// Number of active functions.
    func_count: usize,
    /// Lifecycle state.
    state: KlpObjectState,
    /// Whether this slot is occupied.
    occupied: bool,
    /// Number of enable cycles completed.
    enable_count: u64,
    /// Number of disable cycles completed.
    disable_count: u64,
}

impl KlpObject {
    /// Create an empty (unoccupied) object.
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            funcs: [KlpFuncDesc::empty(); MAX_FUNCS],
            func_count: 0,
            state: KlpObjectState::Loaded,
            occupied: false,
            enable_count: 0,
            disable_count: 0,
        }
    }

    /// Create a new patch object with the given name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `name` is empty or too
    /// long.
    pub fn new(name: &[u8]) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut obj = Self::empty();
        obj.name[..name.len()].copy_from_slice(name);
        obj.name_len = name.len();
        obj.occupied = true;
        Ok(obj)
    }

    /// Add a function replacement to this object.
    ///
    /// # Errors
    ///
    /// - [`Error::Busy`] if the object is not in `Loaded` state.
    /// - [`Error::OutOfMemory`] if the function table is full.
    pub fn add_func(&mut self, func: KlpFuncDesc) -> Result<()> {
        if self.state != KlpObjectState::Loaded {
            return Err(Error::Busy);
        }
        if self.func_count >= MAX_FUNCS {
            return Err(Error::OutOfMemory);
        }
        self.funcs[self.func_count] = func;
        self.func_count += 1;
        Ok(())
    }

    /// Return the object name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the lifecycle state.
    pub const fn state(&self) -> KlpObjectState {
        self.state
    }

    /// Return the number of function replacements.
    pub const fn func_count(&self) -> usize {
        self.func_count
    }

    /// Return whether this object slot is occupied.
    pub const fn is_occupied(&self) -> bool {
        self.occupied
    }

    /// Return a reference to a function by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `idx` is out of bounds.
    pub fn get_func(&self, idx: usize) -> Result<&KlpFuncDesc> {
        if idx >= self.func_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.funcs[idx])
    }

    /// Return the enable count.
    pub const fn enable_count(&self) -> u64 {
        self.enable_count
    }

    /// Return the disable count.
    pub const fn disable_count(&self) -> u64 {
        self.disable_count
    }
}

impl Default for KlpObject {
    fn default() -> Self {
        Self::empty()
    }
}

// -- KlpTransitionKind -------------------------------------------------------

/// Direction of a livepatch transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KlpTransitionKind {
    /// Transitioning tasks from Unpatched to Patched universe.
    Enable,
    /// Transitioning tasks from Patched to Unpatched universe.
    Disable,
}

// -- KlpTransitionEngine -----------------------------------------------------

/// Drives the transition state machine for livepatch operations.
///
/// Manages per-task universe tracking and coordinates the migration
/// of all tasks between universes.
pub struct KlpTransitionEngine {
    /// Per-task transition states.
    tasks: [KlpTaskState; MAX_TASKS],
    /// Number of registered tasks.
    task_count: usize,
    /// Whether a transition is currently in progress.
    in_progress: bool,
    /// Index of the target object being transitioned.
    target_object: usize,
    /// Direction of the current transition.
    kind: KlpTransitionKind,
    /// Target universe for the transition.
    target_universe: KlpUniverse,
    /// Tick when the transition started.
    start_tick: u64,
    /// Force-transition timeout in ticks.
    force_timeout: u64,
    /// Number of tasks that have migrated so far.
    migrated_count: usize,
}

impl KlpTransitionEngine {
    /// Create a new idle transition engine.
    pub const fn new() -> Self {
        Self {
            tasks: [KlpTaskState::empty(); MAX_TASKS],
            task_count: 0,
            in_progress: false,
            target_object: 0,
            kind: KlpTransitionKind::Enable,
            target_universe: KlpUniverse::Patched,
            start_tick: 0,
            force_timeout: DEFAULT_FORCE_TIMEOUT,
            migrated_count: 0,
        }
    }

    /// Register a task for universe tracking.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the table is full.
    /// - [`Error::AlreadyExists`] if the task is already registered.
    pub fn register_task(&mut self, task_id: u64) -> Result<()> {
        if self
            .tasks
            .iter()
            .any(|t| t.occupied && t.task_id == task_id)
        {
            return Err(Error::AlreadyExists);
        }
        let idx = self
            .tasks
            .iter()
            .position(|t| !t.occupied)
            .ok_or(Error::OutOfMemory)?;
        self.tasks[idx] = KlpTaskState {
            task_id,
            universe: KlpUniverse::Unpatched,
            at_safe_point: false,
            occupied: true,
        };
        self.task_count += 1;
        Ok(())
    }

    /// Unregister a task (e.g., on task exit).
    ///
    /// If a transition is in progress and this task has not yet
    /// migrated, it is counted as migrated (it will not execute
    /// either version).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the task is not registered.
    pub fn unregister_task(&mut self, task_id: u64) -> Result<()> {
        for entry in &mut self.tasks {
            if entry.occupied && entry.task_id == task_id {
                if self.in_progress && entry.universe != self.target_universe {
                    self.migrated_count += 1;
                }
                entry.occupied = false;
                self.task_count = self.task_count.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Mark a task as having reached a safe transition point.
    ///
    /// If a transition is in progress, the task is migrated to the
    /// target universe.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the task is not registered.
    pub fn task_safe_point(&mut self, task_id: u64) -> Result<()> {
        for entry in &mut self.tasks {
            if entry.occupied && entry.task_id == task_id {
                entry.at_safe_point = true;
                if self.in_progress && entry.universe != self.target_universe {
                    entry.universe = self.target_universe;
                    self.migrated_count += 1;
                }
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Begin a transition for the given object.
    ///
    /// # Errors
    ///
    /// - [`Error::Busy`] if a transition is already in progress.
    pub fn begin(
        &mut self,
        object_idx: usize,
        kind: KlpTransitionKind,
        current_tick: u64,
    ) -> Result<()> {
        if self.in_progress {
            return Err(Error::Busy);
        }
        self.in_progress = true;
        self.target_object = object_idx;
        self.kind = kind;
        self.target_universe = match kind {
            KlpTransitionKind::Enable => KlpUniverse::Patched,
            KlpTransitionKind::Disable => KlpUniverse::Unpatched,
        };
        self.start_tick = current_tick;
        self.migrated_count = 0;

        // Reset safe-point flags.
        for entry in &mut self.tasks {
            if entry.occupied {
                entry.at_safe_point = false;
            }
        }

        Ok(())
    }

    /// Check whether all tasks have migrated to the target universe.
    pub fn all_migrated(&self) -> bool {
        if !self.in_progress {
            return false;
        }
        self.tasks
            .iter()
            .filter(|t| t.occupied)
            .all(|t| t.universe == self.target_universe)
    }

    /// Check whether the force timeout has elapsed.
    pub fn timed_out(&self, current_tick: u64) -> bool {
        self.in_progress && current_tick.wrapping_sub(self.start_tick) >= self.force_timeout
    }

    /// Force-migrate all remaining tasks to the target universe.
    ///
    /// Should only be called after timeout.
    pub fn force_migrate(&mut self) {
        for entry in &mut self.tasks {
            if entry.occupied && entry.universe != self.target_universe {
                entry.universe = self.target_universe;
                self.migrated_count += 1;
            }
        }
    }

    /// Complete the current transition.
    pub fn complete(&mut self) {
        self.in_progress = false;
    }

    /// Return whether a transition is in progress.
    pub const fn is_active(&self) -> bool {
        self.in_progress
    }

    /// Return the target object index.
    pub const fn target_object(&self) -> usize {
        self.target_object
    }

    /// Return the transition kind.
    pub const fn kind(&self) -> KlpTransitionKind {
        self.kind
    }

    /// Return the number of registered tasks.
    pub const fn task_count(&self) -> usize {
        self.task_count
    }

    /// Return the number of migrated tasks.
    pub const fn migrated_count(&self) -> usize {
        self.migrated_count
    }

    /// Set the force-transition timeout.
    pub fn set_force_timeout(&mut self, ticks: u64) {
        self.force_timeout = ticks;
    }
}

impl Default for KlpTransitionEngine {
    fn default() -> Self {
        Self::new()
    }
}

// -- KlpPatchStatus ----------------------------------------------------------

/// Sysfs-like status entry for a patch object.
///
/// Provides a read-only snapshot of a patch's state for external
/// queries.
#[derive(Clone, Copy)]
pub struct KlpPatchStatus {
    /// Patch object name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Current state.
    pub state: KlpObjectState,
    /// Number of function replacements.
    pub func_count: usize,
    /// Number of enable cycles.
    pub enable_count: u64,
    /// Number of disable cycles.
    pub disable_count: u64,
    /// Whether a transition is targeting this object.
    pub transition_active: bool,
    /// Whether this entry is valid.
    valid: bool,
}

impl KlpPatchStatus {
    /// Create an empty (invalid) status entry.
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            state: KlpObjectState::Loaded,
            func_count: 0,
            enable_count: 0,
            disable_count: 0,
            transition_active: false,
            valid: false,
        }
    }

    /// Return the patch name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return whether this status entry is valid.
    pub const fn is_valid(&self) -> bool {
        self.valid
    }
}

impl Default for KlpPatchStatus {
    fn default() -> Self {
        Self::empty()
    }
}

// -- KlpCore -----------------------------------------------------------------

/// Top-level livepatch manager.
///
/// Coordinates patch object registration, the transition engine,
/// and status reporting. This is the main entry point for livepatch
/// operations.
pub struct KlpCore {
    /// Registered patch objects.
    objects: [KlpObject; MAX_OBJECTS],
    /// Number of occupied object slots.
    object_count: usize,
    /// Transition engine.
    engine: KlpTransitionEngine,
    /// Current tick counter.
    current_tick: u64,
}

impl KlpCore {
    /// Create a new livepatch core manager.
    pub const fn new() -> Self {
        const EMPTY_OBJ: KlpObject = KlpObject::empty();
        Self {
            objects: [EMPTY_OBJ; MAX_OBJECTS],
            object_count: 0,
            engine: KlpTransitionEngine::new(),
            current_tick: 0,
        }
    }

    /// Register a patch object, returning its slot index.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if all slots are occupied.
    /// - [`Error::AlreadyExists`] if an object with the same name
    ///   already exists.
    pub fn register(&mut self, obj: KlpObject) -> Result<usize> {
        let new_name = &obj.name[..obj.name_len];
        for o in &self.objects {
            if o.occupied && o.name() == new_name {
                return Err(Error::AlreadyExists);
            }
        }
        let idx = self
            .objects
            .iter()
            .position(|o| !o.occupied)
            .ok_or(Error::OutOfMemory)?;
        self.objects[idx] = obj;
        self.object_count += 1;
        Ok(idx)
    }

    /// Unregister a patch object.
    ///
    /// The object must be in `Loaded` or `Disabled` state.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `obj_id` is invalid.
    /// - [`Error::Busy`] if the object is enabled or transitioning.
    pub fn unregister(&mut self, obj_id: usize) -> Result<()> {
        if obj_id >= MAX_OBJECTS || !self.objects[obj_id].occupied {
            return Err(Error::NotFound);
        }
        let state = self.objects[obj_id].state;
        if state != KlpObjectState::Loaded && state != KlpObjectState::Disabled {
            return Err(Error::Busy);
        }
        self.objects[obj_id].occupied = false;
        self.object_count = self.object_count.saturating_sub(1);
        Ok(())
    }

    /// Begin enabling a patch object.
    ///
    /// Starts the transition to move all tasks to the Patched
    /// universe, activating function redirects.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `obj_id` is invalid.
    /// - [`Error::Busy`] if a transition is in progress or the
    ///   object is not in `Loaded`/`Disabled` state.
    /// - [`Error::InvalidArgument`] if the object has no functions.
    pub fn enable(&mut self, obj_id: usize) -> Result<()> {
        if obj_id >= MAX_OBJECTS || !self.objects[obj_id].occupied {
            return Err(Error::NotFound);
        }
        let obj = &self.objects[obj_id];
        if obj.state != KlpObjectState::Loaded && obj.state != KlpObjectState::Disabled {
            return Err(Error::Busy);
        }
        if obj.func_count == 0 {
            return Err(Error::InvalidArgument);
        }

        // Activate function redirects.
        for i in 0..self.objects[obj_id].func_count {
            self.objects[obj_id].funcs[i].redirecting = true;
        }
        self.objects[obj_id].state = KlpObjectState::Enabling;

        self.engine
            .begin(obj_id, KlpTransitionKind::Enable, self.current_tick)?;
        Ok(())
    }

    /// Begin disabling a patch object.
    ///
    /// Starts the transition to move all tasks back to the Unpatched
    /// universe, deactivating function redirects.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `obj_id` is invalid.
    /// - [`Error::Busy`] if a transition is in progress or the
    ///   object is not in `Enabled` state.
    pub fn disable(&mut self, obj_id: usize) -> Result<()> {
        if obj_id >= MAX_OBJECTS || !self.objects[obj_id].occupied {
            return Err(Error::NotFound);
        }
        if self.objects[obj_id].state != KlpObjectState::Enabled {
            return Err(Error::Busy);
        }

        self.objects[obj_id].state = KlpObjectState::Disabling;

        self.engine
            .begin(obj_id, KlpTransitionKind::Disable, self.current_tick)?;
        Ok(())
    }

    /// Register a task for livepatch universe tracking.
    ///
    /// Should be called for every new task in the system.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the task table is full.
    /// - [`Error::AlreadyExists`] if the task is already registered.
    pub fn register_task(&mut self, task_id: u64) -> Result<()> {
        self.engine.register_task(task_id)
    }

    /// Unregister a task (e.g., on task exit).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the task is not registered.
    pub fn unregister_task(&mut self, task_id: u64) -> Result<()> {
        self.engine.unregister_task(task_id)
    }

    /// Signal that a task has reached a safe transition point.
    ///
    /// Called from the syscall return path or voluntary schedule
    /// points.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the task is not registered.
    pub fn task_safe_point(&mut self, task_id: u64) -> Result<()> {
        self.engine.task_safe_point(task_id)
    }

    /// Advance the tick counter and progress the transition.
    ///
    /// Should be called from the timer interrupt handler.
    pub fn tick(&mut self) {
        self.current_tick = self.current_tick.wrapping_add(1);

        if !self.engine.is_active() {
            return;
        }

        // Check for normal completion.
        if self.engine.all_migrated() {
            self.finalize_transition();
            return;
        }

        // Check for force timeout.
        if self.engine.timed_out(self.current_tick) {
            self.engine.force_migrate();
            self.finalize_transition();
        }
    }

    /// Force-complete the current transition.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if no transition is active.
    pub fn force_transition(&mut self) -> Result<()> {
        if !self.engine.is_active() {
            return Err(Error::InvalidArgument);
        }
        self.engine.force_migrate();
        self.finalize_transition();
        Ok(())
    }

    /// Return the status of a patch object.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `obj_id` is invalid.
    pub fn status(&self, obj_id: usize) -> Result<KlpPatchStatus> {
        if obj_id >= MAX_OBJECTS || !self.objects[obj_id].occupied {
            return Err(Error::NotFound);
        }
        let obj = &self.objects[obj_id];
        let mut status = KlpPatchStatus::empty();
        status.name[..obj.name_len].copy_from_slice(&obj.name[..obj.name_len]);
        status.name_len = obj.name_len;
        status.state = obj.state;
        status.func_count = obj.func_count;
        status.enable_count = obj.enable_count;
        status.disable_count = obj.disable_count;
        status.transition_active = self.engine.is_active() && self.engine.target_object() == obj_id;
        status.valid = true;
        Ok(status)
    }

    /// Return statuses for all registered patch objects.
    ///
    /// Returns a fixed-size array and the number of valid entries.
    pub fn all_statuses(&self) -> ([KlpPatchStatus; MAX_STATUS_ENTRIES], usize) {
        let mut statuses = [KlpPatchStatus::empty(); MAX_STATUS_ENTRIES];
        let mut count = 0usize;

        for (i, obj) in self.objects.iter().enumerate() {
            if obj.occupied && count < MAX_STATUS_ENTRIES {
                if let Ok(s) = self.status(i) {
                    statuses[count] = s;
                    count += 1;
                }
            }
        }

        (statuses, count)
    }

    /// Return a reference to a patch object by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `obj_id` is invalid.
    pub fn get_object(&self, obj_id: usize) -> Result<&KlpObject> {
        if obj_id >= MAX_OBJECTS || !self.objects[obj_id].occupied {
            return Err(Error::NotFound);
        }
        Ok(&self.objects[obj_id])
    }

    /// Return a reference to the transition engine.
    pub fn engine(&self) -> &KlpTransitionEngine {
        &self.engine
    }

    /// Return the number of registered objects.
    pub const fn object_count(&self) -> usize {
        self.object_count
    }

    /// Return the current tick.
    pub const fn current_tick(&self) -> u64 {
        self.current_tick
    }

    /// Set the force-transition timeout.
    pub fn set_force_timeout(&mut self, ticks: u64) {
        self.engine.set_force_timeout(ticks);
    }

    // -- Internal helpers ----------------------------------------------------

    /// Finalize the current transition by moving the target object
    /// to its terminal state.
    fn finalize_transition(&mut self) {
        let obj_id = self.engine.target_object();
        if obj_id >= MAX_OBJECTS || !self.objects[obj_id].occupied {
            self.engine.complete();
            return;
        }

        match self.engine.kind() {
            KlpTransitionKind::Enable => {
                self.objects[obj_id].state = KlpObjectState::Enabled;
                self.objects[obj_id].enable_count =
                    self.objects[obj_id].enable_count.saturating_add(1);
            }
            KlpTransitionKind::Disable => {
                // Deactivate function redirects.
                for i in 0..self.objects[obj_id].func_count {
                    self.objects[obj_id].funcs[i].redirecting = false;
                }
                self.objects[obj_id].state = KlpObjectState::Disabled;
                self.objects[obj_id].disable_count =
                    self.objects[obj_id].disable_count.saturating_add(1);
            }
        }

        self.engine.complete();
    }
}

impl Default for KlpCore {
    fn default() -> Self {
        Self::new()
    }
}
