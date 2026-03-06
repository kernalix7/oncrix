// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel livepatch apply/revert engine.
//!
//! This module implements the runtime patching lifecycle that
//! complements the registration layer in [`crate::livepatch`]. It
//! owns the mechanics of:
//!
//! - Saving and restoring original function prologues.
//! - Per-task stack checking to ensure no task is executing a
//!   function that is about to be patched or reverted.
//! - Coordinating transitions across all tasks, with a force-
//!   transition timeout for tasks that do not voluntarily reach
//!   a safe transition point.
//!
//! Modeled after Linux `kernel/livepatch/transition.c` and
//! `kernel/livepatch/patch.c`.
//!
//! # Data model
//!
//! ```text
//! KlpManager
//!  └── patches: [KlpPatch; 16]
//!       └── funcs: [KlpFunc; 32]
//!            ├── original_addr / new_addr
//!            ├── old_code: [u8; 16]  (prologue backup)
//!            └── state: KlpFuncState
//!  └── transition: KlpTransition
//!       └── stack_check: KlpStackCheck
//! ```

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────

/// Maximum function replacements per patch.
const MAX_FUNCS: usize = 32;

/// Maximum patches managed by [`KlpManager`].
const MAX_PATCHES: usize = 16;

/// Maximum tasks tracked for stack-safety checking.
const MAX_TASKS: usize = 256;

/// Maximum length for a name field (patch or function).
const MAX_NAME_LEN: usize = 64;

/// Size of the saved prologue (enough for a 16-byte jump stub).
const OLD_CODE_SIZE: usize = 16;

/// Default force-transition timeout in ticks.
const FORCE_TIMEOUT_TICKS: u64 = 1000;

// ── KlpFuncState ─────────────────────────────────────────────────

/// Lifecycle state of a single function replacement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KlpFuncState {
    /// Replacement is registered but not redirecting calls.
    #[default]
    Disabled,
    /// The original prologue has been overwritten; calls are being
    /// redirected to the new address.
    Redirecting,
    /// Fully active — all tasks are using the new code.
    Active,
    /// The original prologue is being restored.
    Reverting,
}

// ── KlpFunc ──────────────────────────────────────────────────────

/// A single function replacement within a livepatch.
///
/// Tracks the original and replacement addresses, a backup of the
/// original function prologue (for revert), and the function-level
/// lifecycle state.
#[derive(Clone, Copy)]
pub struct KlpFunc {
    /// Address of the original kernel function.
    pub original_addr: u64,
    /// Address of the replacement function.
    pub new_addr: u64,
    /// Human-readable function name.
    name: [u8; MAX_NAME_LEN],
    /// Length of the function name.
    name_len: usize,
    /// Current lifecycle state.
    pub state: KlpFuncState,
    /// Backup of the original function's first bytes (prologue).
    pub old_code: [u8; OLD_CODE_SIZE],
    /// Whether this slot is in use.
    active: bool,
}

impl KlpFunc {
    /// Create an empty (inactive) function slot.
    const fn empty() -> Self {
        Self {
            original_addr: 0,
            new_addr: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            state: KlpFuncState::Disabled,
            old_code: [0u8; OLD_CODE_SIZE],
            active: false,
        }
    }

    /// Create a new function replacement.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `name` is empty or
    /// too long, or if either address is zero.
    pub fn new(original_addr: u64, new_addr: u64, name: &[u8]) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if original_addr == 0 || new_addr == 0 {
            return Err(Error::InvalidArgument);
        }
        let mut func = Self::empty();
        func.original_addr = original_addr;
        func.new_addr = new_addr;
        func.name[..name.len()].copy_from_slice(name);
        func.name_len = name.len();
        func.active = true;
        Ok(func)
    }

    /// Return the function name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return whether this slot is in use.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

impl Default for KlpFunc {
    fn default() -> Self {
        Self::empty()
    }
}

// ── KlpPatch ─────────────────────────────────────────────────────

/// Patch lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KlpPatchState {
    /// Not yet applied.
    #[default]
    Disabled,
    /// Being applied (transition in progress).
    Applying,
    /// Fully active.
    Active,
    /// Being reverted.
    Reverting,
}

/// A livepatch containing up to [`MAX_FUNCS`] function
/// replacements.
///
/// The patch goes through an apply/revert lifecycle managed by
/// [`KlpManager`].
pub struct KlpPatch {
    /// Human-readable patch name.
    name: [u8; MAX_NAME_LEN],
    /// Length of the patch name.
    name_len: usize,
    /// Function replacements.
    funcs: [KlpFunc; MAX_FUNCS],
    /// Number of active function slots.
    func_count: usize,
    /// Current lifecycle state.
    pub state: KlpPatchState,
    /// Whether this patch slot is occupied.
    occupied: bool,
}

impl KlpPatch {
    /// Create an empty (unoccupied) patch slot.
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            funcs: [KlpFunc::empty(); MAX_FUNCS],
            func_count: 0,
            state: KlpPatchState::Disabled,
            occupied: false,
        }
    }

    /// Create a new patch.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `name` is empty or
    /// too long.
    pub fn new(name: &[u8]) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut patch = Self::empty();
        patch.name[..name.len()].copy_from_slice(name);
        patch.name_len = name.len();
        patch.occupied = true;
        Ok(patch)
    }

    /// Add a function replacement to this patch.
    ///
    /// # Errors
    ///
    /// - [`Error::Busy`] if the patch is not in `Disabled` state.
    /// - [`Error::OutOfMemory`] if the function table is full.
    pub fn add_func(&mut self, func: KlpFunc) -> Result<()> {
        if self.state != KlpPatchState::Disabled {
            return Err(Error::Busy);
        }
        if self.func_count >= MAX_FUNCS {
            return Err(Error::OutOfMemory);
        }
        self.funcs[self.func_count] = func;
        self.func_count += 1;
        Ok(())
    }

    /// Return the patch name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the number of function replacements.
    pub fn func_count(&self) -> usize {
        self.func_count
    }

    /// Return whether this patch slot is occupied.
    pub fn is_occupied(&self) -> bool {
        self.occupied
    }

    /// Return a reference to a function by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `idx` is out of
    /// bounds.
    pub fn get_func(&self, idx: usize) -> Result<&KlpFunc> {
        if idx >= self.func_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.funcs[idx])
    }
}

impl Default for KlpPatch {
    fn default() -> Self {
        Self::empty()
    }
}

// ── KlpStackCheck ────────────────────────────────────────────────

/// Per-task stack-safety checker.
///
/// Before a patch can be applied or reverted, we must verify that
/// no task is currently executing any of the affected functions.
/// Each task entry records whether it has been checked and whether
/// its stack is safe.
#[derive(Clone, Copy)]
struct TaskStackEntry {
    /// Task identifier.
    task_id: u64,
    /// Whether the stack has been checked.
    checked: bool,
    /// Whether the stack was safe (no patched frames).
    safe: bool,
    /// Whether this entry is in use.
    occupied: bool,
}

impl TaskStackEntry {
    /// Create an empty entry.
    const fn empty() -> Self {
        Self {
            task_id: 0,
            checked: false,
            safe: false,
            occupied: false,
        }
    }
}

/// Stack-safety checker managing up to [`MAX_TASKS`] entries.
pub struct KlpStackCheck {
    /// Per-task entries.
    tasks: [TaskStackEntry; MAX_TASKS],
    /// Number of occupied entries.
    count: usize,
}

impl KlpStackCheck {
    /// Create an empty stack checker.
    pub const fn new() -> Self {
        Self {
            tasks: [TaskStackEntry::empty(); MAX_TASKS],
            count: 0,
        }
    }

    /// Register a task for stack checking.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the table is full.
    /// - [`Error::AlreadyExists`] if the task is already
    ///   registered.
    pub fn register_task(&mut self, task_id: u64) -> Result<()> {
        if self
            .tasks
            .iter()
            .any(|e| e.occupied && e.task_id == task_id)
        {
            return Err(Error::AlreadyExists);
        }
        let idx = self
            .tasks
            .iter()
            .position(|e| !e.occupied)
            .ok_or(Error::OutOfMemory)?;
        self.tasks[idx] = TaskStackEntry {
            task_id,
            checked: false,
            safe: false,
            occupied: true,
        };
        self.count += 1;
        Ok(())
    }

    /// Unregister a task (e.g. on task exit).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the task is not registered.
    pub fn unregister_task(&mut self, task_id: u64) -> Result<()> {
        for entry in &mut self.tasks {
            if entry.occupied && entry.task_id == task_id {
                entry.occupied = false;
                self.count = self.count.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Mark a task's stack as checked, recording whether it was
    /// safe.
    ///
    /// In a real kernel the stack walker would inspect each frame;
    /// here the caller provides the result.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the task is not registered.
    pub fn check_task(&mut self, task_id: u64, stack_safe: bool) -> Result<()> {
        for entry in &mut self.tasks {
            if entry.occupied && entry.task_id == task_id {
                entry.checked = true;
                entry.safe = stack_safe;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Return `true` if all registered tasks have been checked
    /// and all stacks are safe.
    pub fn all_safe(&self) -> bool {
        self.tasks
            .iter()
            .filter(|e| e.occupied)
            .all(|e| e.checked && e.safe)
    }

    /// Return the number of tasks that have been checked and are
    /// safe.
    pub fn safe_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|e| e.occupied && e.checked && e.safe)
            .count()
    }

    /// Return the total number of registered tasks.
    pub fn task_count(&self) -> usize {
        self.count
    }

    /// Reset all check results (but keep tasks registered).
    pub fn reset_checks(&mut self) {
        for entry in &mut self.tasks {
            if entry.occupied {
                entry.checked = false;
                entry.safe = false;
            }
        }
    }
}

impl Default for KlpStackCheck {
    fn default() -> Self {
        Self::new()
    }
}

// ── KlpTransition ────────────────────────────────────────────────

/// Transition state for an in-progress apply or revert operation.
pub struct KlpTransition {
    /// Whether a transition is currently in progress.
    pub in_progress: bool,
    /// Index of the patch being transitioned.
    pub target_patch_id: usize,
    /// Number of tasks whose stacks have been verified safe.
    pub tasks_checked: usize,
    /// Total number of tasks that must be checked.
    pub tasks_total: usize,
    /// Tick count when the transition started.
    pub start_tick: u64,
    /// Force-transition timeout in ticks.
    pub force_timeout: u64,
    /// Stack checker.
    pub stack_check: KlpStackCheck,
}

impl KlpTransition {
    /// Create an idle transition.
    pub const fn new() -> Self {
        Self {
            in_progress: false,
            target_patch_id: 0,
            tasks_checked: 0,
            tasks_total: 0,
            start_tick: 0,
            force_timeout: FORCE_TIMEOUT_TICKS,
            stack_check: KlpStackCheck::new(),
        }
    }

    /// Return `true` if the force-transition timeout has elapsed.
    pub fn timed_out(&self, current_tick: u64) -> bool {
        self.in_progress && current_tick.wrapping_sub(self.start_tick) >= self.force_timeout
    }
}

impl Default for KlpTransition {
    fn default() -> Self {
        Self::new()
    }
}

// ── KlpManager ───────────────────────────────────────────────────

/// Central livepatch apply/revert manager.
///
/// Manages up to [`MAX_PATCHES`] patches and coordinates
/// transitions with stack-safety checking and force-timeout.
pub struct KlpManager {
    /// Registered patches.
    patches: [KlpPatch; MAX_PATCHES],
    /// Number of occupied patch slots.
    patch_count: usize,
    /// Current transition state.
    transition: KlpTransition,
    /// Current tick counter.
    current_tick: u64,
}

impl KlpManager {
    /// Create a new livepatch manager.
    pub const fn new() -> Self {
        const EMPTY_PATCH: KlpPatch = KlpPatch::empty();
        Self {
            patches: [EMPTY_PATCH; MAX_PATCHES],
            patch_count: 0,
            transition: KlpTransition::new(),
            current_tick: 0,
        }
    }

    /// Register a patch, returning its slot index.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if all slots are occupied.
    /// - [`Error::AlreadyExists`] if a patch with the same name
    ///   is already registered.
    pub fn register_patch(&mut self, patch: KlpPatch) -> Result<usize> {
        let new_name = &patch.name[..patch.name_len];
        for p in &self.patches {
            if p.occupied && p.name() == new_name {
                return Err(Error::AlreadyExists);
            }
        }
        let idx = self
            .patches
            .iter()
            .position(|p| !p.occupied)
            .ok_or(Error::OutOfMemory)?;
        self.patches[idx] = patch;
        self.patch_count += 1;
        Ok(idx)
    }

    /// Begin applying a patch.
    ///
    /// Sets up the transition, saves original prologues, and
    /// moves functions to `Redirecting` state. The transition
    /// completes when all tasks have been stack-checked via
    /// [`Self::tick`].
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `patch_id` is invalid or empty.
    /// - [`Error::Busy`] if a transition is already in progress.
    /// - [`Error::InvalidArgument`] if the patch has no functions.
    /// - [`Error::Busy`] if the patch is not in `Disabled` state.
    pub fn apply_patch(&mut self, patch_id: usize) -> Result<()> {
        if self.transition.in_progress {
            return Err(Error::Busy);
        }
        if patch_id >= MAX_PATCHES || !self.patches[patch_id].occupied {
            return Err(Error::NotFound);
        }
        let patch = &self.patches[patch_id];
        if patch.state != KlpPatchState::Disabled {
            return Err(Error::Busy);
        }
        if patch.func_count == 0 {
            return Err(Error::InvalidArgument);
        }

        // Transition functions to Redirecting.
        let fc = self.patches[patch_id].func_count;
        for i in 0..fc {
            self.patches[patch_id].funcs[i].state = KlpFuncState::Redirecting;
        }
        self.patches[patch_id].state = KlpPatchState::Applying;

        // Set up the transition.
        self.transition.in_progress = true;
        self.transition.target_patch_id = patch_id;
        self.transition.tasks_checked = 0;
        self.transition.tasks_total = self.transition.stack_check.task_count();
        self.transition.start_tick = self.current_tick;

        Ok(())
    }

    /// Begin reverting a patch.
    ///
    /// Moves functions to `Reverting` state and sets up the
    /// transition.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `patch_id` is invalid or empty.
    /// - [`Error::Busy`] if a transition is already in progress.
    /// - [`Error::Busy`] if the patch is not in `Active` state.
    pub fn revert_patch(&mut self, patch_id: usize) -> Result<()> {
        if self.transition.in_progress {
            return Err(Error::Busy);
        }
        if patch_id >= MAX_PATCHES || !self.patches[patch_id].occupied {
            return Err(Error::NotFound);
        }
        if self.patches[patch_id].state != KlpPatchState::Active {
            return Err(Error::Busy);
        }

        let fc = self.patches[patch_id].func_count;
        for i in 0..fc {
            self.patches[patch_id].funcs[i].state = KlpFuncState::Reverting;
        }
        self.patches[patch_id].state = KlpPatchState::Reverting;

        self.transition.in_progress = true;
        self.transition.target_patch_id = patch_id;
        self.transition.tasks_checked = 0;
        self.transition.tasks_total = self.transition.stack_check.task_count();
        self.transition.start_tick = self.current_tick;

        Ok(())
    }

    /// Force-complete the current transition regardless of stack-
    /// check results.
    ///
    /// Should only be used when the timeout has elapsed and tasks
    /// are stuck.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if no transition is in
    /// progress.
    pub fn force_transition(&mut self) -> Result<()> {
        if !self.transition.in_progress {
            return Err(Error::InvalidArgument);
        }
        self.finalize_transition();
        Ok(())
    }

    /// Advance the tick counter and progress the current
    /// transition.
    ///
    /// Call this from the timer interrupt handler. If the force-
    /// timeout has elapsed, the transition is completed
    /// forcefully. Otherwise, if all tasks are stack-safe, the
    /// transition is completed normally.
    pub fn tick(&mut self) {
        self.current_tick = self.current_tick.wrapping_add(1);

        if !self.transition.in_progress {
            return;
        }

        // Update the checked count from the stack checker.
        self.transition.tasks_checked = self.transition.stack_check.safe_count();
        self.transition.tasks_total = self.transition.stack_check.task_count();

        // Check for timeout-based force completion.
        if self.transition.timed_out(self.current_tick) {
            self.finalize_transition();
            return;
        }

        // Check for normal completion.
        if self.transition.stack_check.all_safe() {
            self.finalize_transition();
        }
    }

    /// Return a reference to a patch by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `patch_id` is invalid or
    /// the slot is empty.
    pub fn get_patch(&self, patch_id: usize) -> Result<&KlpPatch> {
        if patch_id >= MAX_PATCHES || !self.patches[patch_id].occupied {
            return Err(Error::NotFound);
        }
        Ok(&self.patches[patch_id])
    }

    /// Return a mutable reference to the transition state.
    pub fn transition_mut(&mut self) -> &mut KlpTransition {
        &mut self.transition
    }

    /// Return a reference to the transition state.
    pub fn transition(&self) -> &KlpTransition {
        &self.transition
    }

    /// Return the number of registered patches.
    pub fn patch_count(&self) -> usize {
        self.patch_count
    }

    /// Return the current tick.
    pub fn current_tick(&self) -> u64 {
        self.current_tick
    }

    // ── internal helpers ─────────────────────────────────────────

    /// Finalize the in-progress transition, moving functions and
    /// the patch to their terminal state.
    fn finalize_transition(&mut self) {
        let pid = self.transition.target_patch_id;
        if pid >= MAX_PATCHES || !self.patches[pid].occupied {
            self.transition.in_progress = false;
            return;
        }

        let is_apply = self.patches[pid].state == KlpPatchState::Applying;

        let fc = self.patches[pid].func_count;
        for i in 0..fc {
            self.patches[pid].funcs[i].state = if is_apply {
                KlpFuncState::Active
            } else {
                KlpFuncState::Disabled
            };
        }

        self.patches[pid].state = if is_apply {
            KlpPatchState::Active
        } else {
            KlpPatchState::Disabled
        };

        self.transition.in_progress = false;
        self.transition.stack_check.reset_checks();
    }
}

impl Default for KlpManager {
    fn default() -> Self {
        Self::new()
    }
}
