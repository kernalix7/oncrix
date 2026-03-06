// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel workqueue — deferred work execution with priority scheduling.
//!
//! Provides a fixed-capacity queue for deferring function calls from
//! interrupt context (or other latency-sensitive paths) to a calmer
//! execution context. Work items carry a priority level so that
//! high-priority work is always processed before normal or low-priority
//! work.
//!
//! The queue uses a flat array with no heap allocation, suitable for
//! `#![no_std]` kernel environments.
//!
//! Reference: Linux `kernel/workqueue.c`.

use core::fmt;

use oncrix_lib::{Error, Result};

/// Maximum number of pending work items in a single [`WorkQueue`].
const MAX_WORK_ITEMS: usize = 128;

/// Function signature for work callbacks.
///
/// The `u64` argument is an opaque context value supplied when the work
/// item was submitted.
pub type WorkFn = fn(u64);

/// Priority level for a [`WorkItem`].
///
/// Items with [`High`](WorkPriority::High) priority are dequeued before
/// [`Normal`](WorkPriority::Normal), which are dequeued before
/// [`Low`](WorkPriority::Low).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkPriority {
    /// Processed first — use for latency-sensitive deferred work.
    High,
    /// Default priority for most deferred work.
    Normal,
    /// Processed last — use for background housekeeping.
    Low,
}

impl WorkPriority {
    /// Return a numeric rank where **lower is higher priority**.
    ///
    /// This makes comparison trivial when scanning for the
    /// highest-priority item.
    const fn rank(self) -> u8 {
        match self {
            WorkPriority::High => 0,
            WorkPriority::Normal => 1,
            WorkPriority::Low => 2,
        }
    }
}

/// A single unit of deferred work.
#[derive(Clone, Copy)]
pub struct WorkItem {
    /// Unique identifier assigned at submission time.
    pub id: u64,
    /// The function to invoke when this item is processed.
    pub func: WorkFn,
    /// Opaque value passed to `func` when invoked.
    pub context: u64,
    /// Scheduling priority.
    pub priority: WorkPriority,
}

impl fmt::Debug for WorkItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkItem")
            .field("id", &self.id)
            .field("context", &self.context)
            .field("priority", &self.priority)
            .finish_non_exhaustive()
    }
}

/// No-op placeholder used to initialise empty slots.
fn noop_work(_ctx: u64) {}

impl WorkItem {
    /// Create an empty (inactive) work item used for array initialisation.
    const fn empty() -> Self {
        Self {
            id: 0,
            func: noop_work,
            context: 0,
            priority: WorkPriority::Low,
        }
    }
}

/// A fixed-capacity, priority-aware queue for deferred work.
///
/// Work items are stored in a flat array of [`MAX_WORK_ITEMS`] slots.
/// Submission fills the first free slot; processing scans for the
/// highest-priority occupied slot, executes it, and marks the slot free.
///
/// This design trades O(n) scan cost for zero heap allocation and
/// simplicity — acceptable at n = 128.
pub struct WorkQueue {
    /// Storage for work items; `active[i]` indicates whether `items[i]`
    /// holds a pending item.
    items: [WorkItem; MAX_WORK_ITEMS],
    /// Per-slot active flag.
    active: [bool; MAX_WORK_ITEMS],
    /// Number of currently pending items (cached to avoid scanning).
    count: usize,
    /// Monotonically increasing ID counter.
    next_id: u64,
}

impl WorkQueue {
    /// Create a new, empty work queue.
    pub const fn new() -> Self {
        Self {
            items: [WorkItem::empty(); MAX_WORK_ITEMS],
            active: [false; MAX_WORK_ITEMS],
            count: 0,
            next_id: 1,
        }
    }

    /// Submit a work item to the queue.
    ///
    /// Returns the unique work ID assigned to the item on success.
    /// Fails with [`Error::OutOfMemory`] if the queue is full.
    pub fn submit(&mut self, func: WorkFn, context: u64, priority: WorkPriority) -> Result<u64> {
        let slot = self.find_free_slot().ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        self.items[slot] = WorkItem {
            id,
            func,
            context,
            priority,
        };
        self.active[slot] = true;
        self.count = self.count.saturating_add(1);

        Ok(id)
    }

    /// Dequeue and execute the highest-priority pending work item.
    ///
    /// Returns `Some(id)` with the executed item's ID, or `None` if the
    /// queue is empty. When multiple items share the highest priority,
    /// the one in the lowest array index (earliest submitted among
    /// equal-priority items) is chosen (FIFO within a priority level).
    pub fn process_one(&mut self) -> Option<u64> {
        let idx = self.find_highest_priority()?;

        let item = self.items[idx];
        self.active[idx] = false;
        self.count = self.count.saturating_sub(1);

        (item.func)(item.context);

        Some(item.id)
    }

    /// Process all pending work items in priority order.
    ///
    /// Returns the number of items that were executed.
    pub fn process_all(&mut self) -> usize {
        let mut processed = 0usize;
        while self.process_one().is_some() {
            processed = processed.saturating_add(1);
        }
        processed
    }

    /// Cancel a pending work item by its ID.
    ///
    /// Returns [`Error::NotFound`] if no pending item with the given ID
    /// exists (it may have already been processed or never submitted).
    pub fn cancel(&mut self, id: u64) -> Result<()> {
        for i in 0..MAX_WORK_ITEMS {
            if self.active[i] && self.items[i].id == id {
                self.active[i] = false;
                self.count = self.count.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Return the number of pending (not yet processed) work items.
    pub fn pending_count(&self) -> usize {
        self.count
    }

    /// Return `true` if there are no pending work items.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Find the first inactive slot index.
    fn find_free_slot(&self) -> Option<usize> {
        self.active.iter().position(|&a| !a)
    }

    /// Find the index of the highest-priority active item.
    ///
    /// Among items with equal priority the lowest index wins, which
    /// preserves FIFO order within each priority level because
    /// [`submit`](Self::submit) always fills the first free slot.
    fn find_highest_priority(&self) -> Option<usize> {
        let mut best: Option<usize> = None;
        let mut best_rank: u8 = u8::MAX;

        for i in 0..MAX_WORK_ITEMS {
            if self.active[i] {
                let rank = self.items[i].priority.rank();
                if rank < best_rank {
                    best_rank = rank;
                    best = Some(i);
                    // Can't beat rank 0 (High).
                    if best_rank == 0 {
                        break;
                    }
                }
            }
        }

        best
    }
}

impl Default for WorkQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for WorkQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkQueue")
            .field("pending", &self.count)
            .field("capacity", &MAX_WORK_ITEMS)
            .field("next_id", &self.next_id)
            .finish()
    }
}

// ======================================================================
// Tasklet — persistent, re-schedulable deferred work units
// ======================================================================

/// Maximum number of tasklets that can be registered simultaneously.
const MAX_TASKLETS: usize = 64;

/// Maximum length of a tasklet name (stored in a fixed-size buffer).
const TASKLET_NAME_LEN: usize = 16;

/// Execution state of a [`Tasklet`].
///
/// State transitions:
/// - `Idle` → `Scheduled` (via [`TaskletQueue::schedule`])
/// - `Scheduled` → `Running` (via [`TaskletQueue::process_all`])
/// - `Running` → `Idle` (after callback completes)
/// - Any state can coexist with a non-zero disable counter; a disabled
///   tasklet will not transition from `Scheduled` to `Running`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskletState {
    /// The tasklet is registered but not pending execution.
    Idle,
    /// The tasklet has been scheduled and is awaiting execution.
    Scheduled,
    /// The tasklet callback is currently executing.
    Running,
    /// The slot is not occupied by any registered tasklet.
    Disabled,
}

/// A persistent, re-schedulable unit of deferred work.
///
/// Unlike [`WorkItem`], which is consumed upon execution, a `Tasklet`
/// is registered once and can be scheduled for execution many times.
/// This makes tasklets ideal for recurring deferred work such as
/// bottom-half interrupt processing.
///
/// Each tasklet carries a disable counter: when the counter is
/// non-zero the tasklet will not be executed even if scheduled.
/// This allows safe temporary suppression without unregistering.
#[derive(Clone, Copy)]
pub struct Tasklet {
    /// Human-readable name for debugging (fixed buffer, NUL-padded).
    name: [u8; TASKLET_NAME_LEN],
    /// The function invoked when this tasklet is processed.
    func: WorkFn,
    /// Opaque context value passed to `func`.
    context: u64,
    /// Current execution state.
    state: TaskletState,
    /// Disable counter — tasklet runs only when this is zero.
    disable_count: u32,
    /// Whether this slot holds a registered tasklet.
    registered: bool,
}

impl fmt::Debug for Tasklet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tasklet")
            .field("name", &self.name_str())
            .field("state", &self.state)
            .field("disable_count", &self.disable_count)
            .finish()
    }
}

impl Tasklet {
    /// Create an empty (unregistered) tasklet for array initialisation.
    const fn empty() -> Self {
        Self {
            name: [0u8; TASKLET_NAME_LEN],
            func: noop_work,
            context: 0,
            state: TaskletState::Disabled,
            disable_count: 0,
            registered: false,
        }
    }

    /// Return the tasklet name as a `&str` (up to the first NUL byte).
    ///
    /// Falls back to `"<invalid>"` if the stored bytes are not valid
    /// UTF-8, which should not happen because [`TaskletQueue::register`]
    /// copies from a `&str`.
    pub fn name_str(&self) -> &str {
        let len = self
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(TASKLET_NAME_LEN);
        core::str::from_utf8(&self.name[..len]).unwrap_or("<invalid>")
    }

    /// Return the current [`TaskletState`].
    pub fn state(&self) -> TaskletState {
        self.state
    }

    /// Return `true` if the tasklet is currently disabled.
    pub fn is_disabled(&self) -> bool {
        self.disable_count > 0
    }
}

/// A fixed-capacity registry of [`Tasklet`]s with scheduling support.
///
/// Tasklets are registered once via [`register`](Self::register) and
/// receive a stable ID (array index). They can then be
/// [`schedule`](Self::schedule)d for execution any number of times.
/// [`process_all`](Self::process_all) runs every scheduled (and
/// enabled) tasklet exactly once per call.
///
/// Capacity: [`MAX_TASKLETS`] (64) slots.
pub struct TaskletQueue {
    /// Tasklet storage; `slots[i].registered` indicates occupancy.
    slots: [Tasklet; MAX_TASKLETS],
    /// Number of currently registered tasklets (cached).
    registered_count: usize,
}

impl TaskletQueue {
    /// Create a new, empty tasklet queue.
    pub const fn new() -> Self {
        Self {
            slots: [Tasklet::empty(); MAX_TASKLETS],
            registered_count: 0,
        }
    }

    /// Register a new tasklet.
    ///
    /// `name` is truncated to [`TASKLET_NAME_LEN`] bytes if longer.
    /// Returns the tasklet ID (slot index) on success.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if all slots are occupied.
    pub fn register(&mut self, name: &str, func: WorkFn, context: u64) -> Result<usize> {
        let slot = self.find_free_slot().ok_or(Error::OutOfMemory)?;

        let mut name_buf = [0u8; TASKLET_NAME_LEN];
        let copy_len = name.len().min(TASKLET_NAME_LEN);
        name_buf[..copy_len].copy_from_slice(&name.as_bytes()[..copy_len]);

        self.slots[slot] = Tasklet {
            name: name_buf,
            func,
            context,
            state: TaskletState::Idle,
            disable_count: 0,
            registered: true,
        };
        self.registered_count = self.registered_count.saturating_add(1);

        Ok(slot)
    }

    /// Schedule a registered tasklet for execution.
    ///
    /// The tasklet must be in the [`Idle`](TaskletState::Idle) state.
    /// If it is already `Scheduled` or `Running`, the call is a no-op
    /// and returns `Ok(())` (idempotent scheduling).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `id` is out of range.
    /// - [`Error::NotFound`] if the slot is not registered.
    pub fn schedule(&mut self, id: usize) -> Result<()> {
        let tasklet = self.get_registered_mut(id)?;
        if tasklet.state == TaskletState::Idle {
            tasklet.state = TaskletState::Scheduled;
        }
        Ok(())
    }

    /// Increment the disable counter for a tasklet.
    ///
    /// While the counter is non-zero the tasklet will not be executed
    /// by [`process_all`](Self::process_all), even if scheduled.
    /// Calls to `disable` nest — each must be paired with a
    /// corresponding [`enable`](Self::enable).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `id` is out of range.
    /// - [`Error::NotFound`] if the slot is not registered.
    pub fn disable(&mut self, id: usize) -> Result<()> {
        let tasklet = self.get_registered_mut(id)?;
        tasklet.disable_count = tasklet.disable_count.saturating_add(1);
        Ok(())
    }

    /// Decrement the disable counter for a tasklet.
    ///
    /// When the counter reaches zero the tasklet becomes eligible for
    /// execution again. It is safe to call `enable` when the counter
    /// is already zero (the call is a no-op).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `id` is out of range.
    /// - [`Error::NotFound`] if the slot is not registered.
    pub fn enable(&mut self, id: usize) -> Result<()> {
        let tasklet = self.get_registered_mut(id)?;
        tasklet.disable_count = tasklet.disable_count.saturating_sub(1);
        Ok(())
    }

    /// Execute all scheduled and enabled tasklets.
    ///
    /// Each tasklet that is in the [`Scheduled`](TaskletState::Scheduled)
    /// state **and** has a disable counter of zero is executed exactly
    /// once. The tasklet transitions through `Running` back to `Idle`.
    ///
    /// Returns the number of tasklets that were executed.
    pub fn process_all(&mut self) -> usize {
        let mut executed = 0usize;

        for i in 0..MAX_TASKLETS {
            if !self.slots[i].registered {
                continue;
            }
            if self.slots[i].state != TaskletState::Scheduled {
                continue;
            }
            if self.slots[i].disable_count > 0 {
                continue;
            }

            // Transition to Running, invoke, then back to Idle.
            self.slots[i].state = TaskletState::Running;
            let func = self.slots[i].func;
            let ctx = self.slots[i].context;
            (func)(ctx);
            self.slots[i].state = TaskletState::Idle;

            executed = executed.saturating_add(1);
        }

        executed
    }

    /// Unregister a tasklet, freeing its slot for reuse.
    ///
    /// The tasklet must not be in the [`Running`](TaskletState::Running)
    /// state. If it is currently `Scheduled`, the pending execution is
    /// silently cancelled.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `id` is out of range.
    /// - [`Error::NotFound`] if the slot is not registered.
    /// - [`Error::Busy`] if the tasklet is currently running.
    pub fn unregister(&mut self, id: usize) -> Result<()> {
        let tasklet = self.get_registered_mut(id)?;
        if tasklet.state == TaskletState::Running {
            return Err(Error::Busy);
        }
        *tasklet = Tasklet::empty();
        self.registered_count = self.registered_count.saturating_sub(1);
        Ok(())
    }

    /// Return the number of currently registered tasklets.
    pub fn registered_count(&self) -> usize {
        self.registered_count
    }

    /// Return a shared reference to a registered tasklet.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `id >= MAX_TASKLETS`.
    /// - [`Error::NotFound`] if the slot is not registered.
    pub fn get(&self, id: usize) -> Result<&Tasklet> {
        if id >= MAX_TASKLETS {
            return Err(Error::InvalidArgument);
        }
        if !self.slots[id].registered {
            return Err(Error::NotFound);
        }
        Ok(&self.slots[id])
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Find the first unoccupied slot index.
    fn find_free_slot(&self) -> Option<usize> {
        self.slots.iter().position(|t| !t.registered)
    }

    /// Return a mutable reference to a registered tasklet, or an
    /// appropriate error.
    fn get_registered_mut(&mut self, id: usize) -> Result<&mut Tasklet> {
        if id >= MAX_TASKLETS {
            return Err(Error::InvalidArgument);
        }
        if !self.slots[id].registered {
            return Err(Error::NotFound);
        }
        Ok(&mut self.slots[id])
    }
}

impl Default for TaskletQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for TaskletQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskletQueue")
            .field("registered", &self.registered_count)
            .field("capacity", &MAX_TASKLETS)
            .finish()
    }
}
