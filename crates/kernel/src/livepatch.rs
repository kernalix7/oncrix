// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel livepatch framework.
//!
//! Provides infrastructure for applying and reverting kernel
//! patches at runtime without rebooting. This is modeled after
//! the Linux kernel livepatching subsystem (`kernel/livepatch/`).
//!
//! Key components:
//!
//! - [`PatchFunc`]: describes a single function replacement
//!   (original address mapped to a replacement).
//! - [`LivePatch`]: a named patch containing up to 32 function
//!   replacements, with enable/disable lifecycle.
//! - [`PatchRegistry`]: manages up to 16 registered patches.
//! - [`ConsistencyModel`]: defines how the transition between
//!   patched and unpatched states is managed.
//! - [`TransitionState`]: tracks per-task transition progress
//!   for stack-checking consistency.
//!
//! Reference: Linux `kernel/livepatch/`, `Documentation/livepatch/`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────

/// Maximum number of function replacements per patch.
const MAX_FUNCS: usize = 32;

/// Maximum number of registered patches.
const MAX_PATCHES: usize = 16;

/// Maximum number of tasks tracked for transition.
const MAX_TASKS: usize = 256;

/// Maximum length of a patch or function name.
const MAX_NAME_LEN: usize = 64;

// ── PatchState ───────────────────────────────────────────────────

/// Lifecycle state of a livepatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchState {
    /// Patch is registered but not active.
    Disabled,
    /// Patch is being activated (transition in progress).
    Enabling,
    /// Patch is fully active.
    Enabled,
    /// Patch is being deactivated (transition in progress).
    Disabling,
}

// ── PatchFunc ────────────────────────────────────────────────────

/// A single function replacement within a livepatch.
///
/// Maps an original kernel function at `original_addr` to a
/// replacement function at `replacement_addr`. The `old_size`
/// field records the size of the original function for
/// validation.
#[derive(Clone, Copy)]
pub struct PatchFunc {
    /// Address of the original function to be patched.
    pub original_addr: u64,
    /// Address of the replacement function.
    pub replacement_addr: u64,
    /// Human-readable function name.
    name: [u8; MAX_NAME_LEN],
    /// Length of the function name.
    name_len: usize,
    /// Size of the original function in bytes (for validation).
    pub old_size: usize,
    /// Whether this function slot is active.
    active: bool,
}

impl PatchFunc {
    /// Create a new empty (inactive) function patch slot.
    const fn empty() -> Self {
        Self {
            original_addr: 0,
            replacement_addr: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            old_size: 0,
            active: false,
        }
    }

    /// Create a new function patch.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `name` is empty
    /// or too long, or if addresses are zero.
    pub fn new(
        original_addr: u64,
        replacement_addr: u64,
        name: &[u8],
        old_size: usize,
    ) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if original_addr == 0 || replacement_addr == 0 {
            return Err(Error::InvalidArgument);
        }
        let mut func = Self::empty();
        func.original_addr = original_addr;
        func.replacement_addr = replacement_addr;
        func.name[..name.len()].copy_from_slice(name);
        func.name_len = name.len();
        func.old_size = old_size;
        func.active = true;
        Ok(func)
    }

    /// Return the function name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return whether this function slot is active.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

// ── LivePatch ────────────────────────────────────────────────────

/// A kernel livepatch containing a set of function replacements.
///
/// A patch transitions through the lifecycle:
/// `Disabled -> Enabling -> Enabled -> Disabling -> Disabled`.
pub struct LivePatch {
    /// Human-readable patch name.
    name: [u8; MAX_NAME_LEN],
    /// Length of the patch name.
    name_len: usize,
    /// Module that owns this patch (for reference counting).
    module_owner: [u8; MAX_NAME_LEN],
    /// Length of the module owner name.
    module_owner_len: usize,
    /// Function replacements.
    funcs: [PatchFunc; MAX_FUNCS],
    /// Number of active function replacements.
    func_count: usize,
    /// Current lifecycle state.
    state: PatchState,
}

impl LivePatch {
    /// Create a new disabled livepatch.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `name` or
    /// `module_owner` is empty or too long.
    pub fn new(name: &[u8], module_owner: &[u8]) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if module_owner.is_empty() || module_owner.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut patch = Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: name.len(),
            module_owner: [0u8; MAX_NAME_LEN],
            module_owner_len: module_owner.len(),
            funcs: [PatchFunc::empty(); MAX_FUNCS],
            func_count: 0,
            state: PatchState::Disabled,
        };
        patch.name[..name.len()].copy_from_slice(name);
        patch.module_owner[..module_owner.len()].copy_from_slice(module_owner);
        Ok(patch)
    }

    /// Add a function replacement to this patch.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the patch already has
    ///   [`MAX_FUNCS`] functions.
    /// - [`Error::Busy`] if the patch is not in [`PatchState::Disabled`].
    pub fn add_func(&mut self, func: PatchFunc) -> Result<()> {
        if self.state != PatchState::Disabled {
            return Err(Error::Busy);
        }
        if self.func_count >= MAX_FUNCS {
            return Err(Error::OutOfMemory);
        }
        self.funcs[self.func_count] = func;
        self.func_count += 1;
        Ok(())
    }

    /// Enable (activate) this patch.
    ///
    /// Transitions from `Disabled` -> `Enabling` -> `Enabled`.
    /// In a real implementation, this would redirect function
    /// calls through the ftrace framework.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the patch has no functions.
    /// - [`Error::Busy`] if the patch is not in
    ///   [`PatchState::Disabled`].
    pub fn enable(&mut self) -> Result<()> {
        if self.state != PatchState::Disabled {
            return Err(Error::Busy);
        }
        if self.func_count == 0 {
            return Err(Error::InvalidArgument);
        }

        self.state = PatchState::Enabling;

        // In a real kernel, we would:
        // 1. Register ftrace handlers for each original_addr.
        // 2. Wait for all tasks to transition (consistency model).
        // 3. Mark each function replacement as active.

        self.state = PatchState::Enabled;
        Ok(())
    }

    /// Disable (deactivate) this patch.
    ///
    /// Transitions from `Enabled` -> `Disabling` -> `Disabled`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the patch is not in
    /// [`PatchState::Enabled`].
    pub fn disable(&mut self) -> Result<()> {
        if self.state != PatchState::Enabled {
            return Err(Error::Busy);
        }

        self.state = PatchState::Disabling;

        // In a real kernel, we would:
        // 1. Remove ftrace handlers.
        // 2. Wait for all tasks to transition back.

        self.state = PatchState::Disabled;
        Ok(())
    }

    /// Return the current patch state.
    pub fn state(&self) -> PatchState {
        self.state
    }

    /// Return the patch name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the module owner name as a byte slice.
    pub fn module_owner(&self) -> &[u8] {
        &self.module_owner[..self.module_owner_len]
    }

    /// Return the number of function replacements.
    pub fn func_count(&self) -> usize {
        self.func_count
    }

    /// Return a reference to a function replacement by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of
    /// bounds.
    pub fn get_func(&self, index: usize) -> Result<&PatchFunc> {
        if index >= self.func_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.funcs[index])
    }
}

// ── ConsistencyModel ─────────────────────────────────────────────

/// Consistency model for livepatch transitions.
///
/// Determines how the kernel ensures that all running tasks
/// observe a consistent set of patched or unpatched functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsistencyModel {
    /// All tasks switch to the patched version immediately.
    ///
    /// Fastest but does not guarantee stack safety: a task
    /// currently executing the old function will finish its
    /// call before seeing the new version.
    ImmediateSwitch,

    /// Tasks are individually transitioned when they are not
    /// executing patched functions (verified via stack checking).
    ///
    /// This is the safe model used by Linux kpatch/livepatch.
    /// Each task is checked at safe transition points (e.g.,
    /// syscall entry/exit, signal delivery) and switched when
    /// its stack does not contain frames from patched functions.
    StackChecking,
}

// ── TaskTransition ───────────────────────────────────────────────

/// Per-task transition state for stack-checking consistency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TaskPatchState {
    /// Task is using the unpatched (original) function versions.
    Unpatched,
    /// Task has been transitioned to the patched versions.
    Patched,
}

/// A single task's transition record.
#[derive(Clone, Copy)]
struct TaskTransitionEntry {
    /// Task ID (kernel thread or user-space task).
    task_id: u64,
    /// Current patch state of this task.
    patch_state: TaskPatchState,
    /// Whether this entry is occupied.
    occupied: bool,
}

impl TaskTransitionEntry {
    /// Create an empty entry.
    const fn empty() -> Self {
        Self {
            task_id: 0,
            patch_state: TaskPatchState::Unpatched,
            occupied: false,
        }
    }
}

/// Tracks per-task transition progress during a livepatch
/// operation.
///
/// When using [`ConsistencyModel::StackChecking`], each task
/// must be individually transitioned at a safe point. This
/// structure tracks which tasks have been transitioned and
/// which are still pending.
pub struct TransitionState {
    /// Per-task transition entries.
    tasks: [TaskTransitionEntry; MAX_TASKS],
    /// Number of tracked tasks.
    count: usize,
    /// The consistency model in effect.
    model: ConsistencyModel,
    /// Target state for the current transition.
    target: TaskPatchState,
}

impl TransitionState {
    /// Create a new transition state tracker.
    pub const fn new(model: ConsistencyModel) -> Self {
        const EMPTY: TaskTransitionEntry = TaskTransitionEntry::empty();
        Self {
            tasks: [EMPTY; MAX_TASKS],
            count: 0,
            model,
            target: TaskPatchState::Patched,
        }
    }

    /// Register a task for transition tracking.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the task table is full.
    /// - [`Error::AlreadyExists`] if the task is already
    ///   registered.
    pub fn register_task(&mut self, task_id: u64) -> Result<()> {
        // Check for duplicates.
        for entry in self.tasks.iter().take(MAX_TASKS) {
            if entry.occupied && entry.task_id == task_id {
                return Err(Error::AlreadyExists);
            }
        }

        let idx = self
            .tasks
            .iter()
            .position(|e| !e.occupied)
            .ok_or(Error::OutOfMemory)?;

        self.tasks[idx] = TaskTransitionEntry {
            task_id,
            patch_state: TaskPatchState::Unpatched,
            occupied: true,
        };
        self.count += 1;
        Ok(())
    }

    /// Unregister a task (e.g., on task exit).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the task is not registered.
    pub fn unregister_task(&mut self, task_id: u64) -> Result<()> {
        for entry in self.tasks.iter_mut() {
            if entry.occupied && entry.task_id == task_id {
                entry.occupied = false;
                self.count = self.count.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Mark a task as having transitioned to the target state.
    ///
    /// This should be called when a task reaches a safe
    /// transition point and its stack has been verified to not
    /// contain frames from patched functions.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the task is not registered.
    pub fn transition_task(&mut self, task_id: u64) -> Result<()> {
        for entry in self.tasks.iter_mut() {
            if entry.occupied && entry.task_id == task_id {
                entry.patch_state = self.target;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Check whether all registered tasks have completed the
    /// transition.
    pub fn is_complete(&self) -> bool {
        for entry in &self.tasks {
            if entry.occupied && entry.patch_state != self.target {
                return false;
            }
        }
        true
    }

    /// Return the number of tasks that have completed the
    /// transition.
    pub fn transitioned_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|e| e.occupied && e.patch_state == self.target)
            .count()
    }

    /// Return the number of tasks still pending transition.
    pub fn pending_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|e| e.occupied && e.patch_state != self.target)
            .count()
    }

    /// Return the total number of tracked tasks.
    pub fn task_count(&self) -> usize {
        self.count
    }

    /// Return the consistency model in effect.
    pub fn model(&self) -> ConsistencyModel {
        self.model
    }

    /// Set the target state for the transition.
    ///
    /// Call with `patched = true` when enabling a patch, or
    /// `patched = false` when disabling.
    pub fn set_target_patched(&mut self, patched: bool) {
        self.target = if patched {
            TaskPatchState::Patched
        } else {
            TaskPatchState::Unpatched
        };
    }

    /// Reset all task states back to unpatched.
    pub fn reset(&mut self) {
        for entry in self.tasks.iter_mut() {
            if entry.occupied {
                entry.patch_state = TaskPatchState::Unpatched;
            }
        }
        self.target = TaskPatchState::Patched;
    }
}

// ── PatchRegistry ────────────────────────────────────────────────

/// Slot in the patch registry.
struct PatchRegistrySlot {
    /// The livepatch.
    patch: Option<LivePatch>,
}

impl PatchRegistrySlot {
    /// Create an empty slot.
    const fn empty() -> Self {
        Self { patch: None }
    }

    /// Return whether this slot is occupied.
    fn is_occupied(&self) -> bool {
        self.patch.is_some()
    }
}

/// Global registry managing up to [`MAX_PATCHES`] livepatches.
///
/// Provides registration, lookup, enable/disable operations
/// for all livepatches in the system.
pub struct PatchRegistry {
    /// Patch slots.
    slots: [PatchRegistrySlot; MAX_PATCHES],
    /// Number of registered patches.
    count: usize,
}

impl Default for PatchRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PatchRegistry {
    /// Create an empty patch registry.
    pub const fn new() -> Self {
        const EMPTY: PatchRegistrySlot = PatchRegistrySlot::empty();
        Self {
            slots: [EMPTY; MAX_PATCHES],
            count: 0,
        }
    }

    /// Register a new livepatch.
    ///
    /// Returns the patch ID (slot index) on success.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if all slots are occupied.
    /// - [`Error::AlreadyExists`] if a patch with the same name
    ///   is already registered.
    pub fn register(&mut self, patch: LivePatch) -> Result<usize> {
        // Check for duplicate name.
        let new_name = &patch.name[..patch.name_len];
        for slot in &self.slots {
            if let Some(existing) = &slot.patch {
                if existing.name() == new_name {
                    return Err(Error::AlreadyExists);
                }
            }
        }

        let idx = self
            .slots
            .iter()
            .position(|s| !s.is_occupied())
            .ok_or(Error::OutOfMemory)?;

        self.slots[idx].patch = Some(patch);
        self.count += 1;
        Ok(idx)
    }

    /// Unregister a livepatch by ID.
    ///
    /// The patch must be in [`PatchState::Disabled`] before it
    /// can be unregistered.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the ID is invalid or empty.
    /// - [`Error::Busy`] if the patch is not disabled.
    pub fn unregister(&mut self, id: usize) -> Result<()> {
        if id >= MAX_PATCHES {
            return Err(Error::NotFound);
        }
        let patch = self.slots[id].patch.as_ref().ok_or(Error::NotFound)?;
        if patch.state() != PatchState::Disabled {
            return Err(Error::Busy);
        }
        self.slots[id].patch = None;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Enable a registered patch by ID.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the ID is invalid or empty.
    /// - Propagates errors from [`LivePatch::enable`].
    pub fn enable(&mut self, id: usize) -> Result<()> {
        if id >= MAX_PATCHES {
            return Err(Error::NotFound);
        }
        let patch = self.slots[id].patch.as_mut().ok_or(Error::NotFound)?;
        patch.enable()
    }

    /// Disable a registered patch by ID.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the ID is invalid or empty.
    /// - Propagates errors from [`LivePatch::disable`].
    pub fn disable(&mut self, id: usize) -> Result<()> {
        if id >= MAX_PATCHES {
            return Err(Error::NotFound);
        }
        let patch = self.slots[id].patch.as_mut().ok_or(Error::NotFound)?;
        patch.disable()
    }

    /// Find a patch by name, returning its ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no patch with the given
    /// name is registered.
    pub fn find(&self, name: &[u8]) -> Result<usize> {
        for (i, slot) in self.slots.iter().enumerate() {
            if let Some(patch) = &slot.patch {
                if patch.name() == name {
                    return Ok(i);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Get a reference to a registered patch by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the ID is invalid or empty.
    pub fn get(&self, id: usize) -> Result<&LivePatch> {
        if id >= MAX_PATCHES {
            return Err(Error::NotFound);
        }
        self.slots[id].patch.as_ref().ok_or(Error::NotFound)
    }

    /// Get a mutable reference to a registered patch by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the ID is invalid or empty.
    pub fn get_mut(&mut self, id: usize) -> Result<&mut LivePatch> {
        if id >= MAX_PATCHES {
            return Err(Error::NotFound);
        }
        self.slots[id].patch.as_mut().ok_or(Error::NotFound)
    }

    /// Return the number of registered patches.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Return whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
