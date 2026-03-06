// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RCU callback processing.
//!
//! Manages the lifecycle of RCU (Read-Copy-Update) callbacks. When a
//! writer updates shared data, the old data's cleanup function is
//! enqueued as an RCU callback. The callback runs only after a
//! grace period ensures no reader holds a reference to the old data.
//!
//! # Segmented Callback List
//!
//! Callbacks are organized into four segments based on their
//! relationship to grace periods:
//!
//! ```text
//! ┌───────────────────────────────────────────────────┐
//! │  DONE      │ ready to invoke (GP completed)       │
//! │  WAIT      │ waiting for current GP to end        │
//! │  NEXT_READY│ assigned to next GP                  │
//! │  NEXT      │ not yet assigned a GP number         │
//! └───────────────────────────────────────────────────┘
//! ```
//!
//! When a GP completes, WAIT → DONE, NEXT_READY → WAIT, etc.
//!
//! # Reference
//!
//! Linux `kernel/rcu/rcu_segcblist.c`, `kernel/rcu/tree.c`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Number of callback segments.
const NUM_SEGMENTS: usize = 4;

/// Maximum callbacks per segment.
const MAX_CBS_PER_SEGMENT: usize = 512;

/// Total maximum callbacks across all segments.
const _MAX_TOTAL_CBS: usize = NUM_SEGMENTS * MAX_CBS_PER_SEGMENT;

/// Maximum number of CPUs.
const MAX_CPUS: usize = 64;

/// Segment indices.
const SEG_DONE: usize = 0;
const SEG_WAIT: usize = 1;
const SEG_NEXT_READY: usize = 2;
const SEG_NEXT: usize = 3;

/// Batch invocation limit (to avoid holding the CPU too long).
const INVOKE_BATCH_LIMIT: usize = 64;

// ======================================================================
// Callback entry
// ======================================================================

/// Identifies the type of cleanup operation for a callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackType {
    /// Free a slab object.
    SlabFree,
    /// Release a page.
    PageRelease,
    /// Destroy a task structure.
    TaskDestroy,
    /// Release an inode.
    InodeRelease,
    /// Generic deferred work.
    DeferredWork,
    /// File descriptor table cleanup.
    FdTableCleanup,
    /// Network buffer free.
    NetBufFree,
    /// Module unload completion.
    ModuleUnload,
}

/// A single RCU callback entry.
#[derive(Debug, Clone, Copy)]
pub struct RcuCallbackEntry {
    /// Type of callback (acts as a function index).
    cb_type: CallbackType,
    /// Opaque argument (pointer-as-u64 or index).
    arg: u64,
    /// Grace period generation this callback is waiting for.
    generation: u64,
    /// Whether this slot is occupied.
    occupied: bool,
    /// Sequence number for ordering within a segment.
    seq: u64,
}

impl RcuCallbackEntry {
    /// Creates an empty callback entry.
    pub const fn new() -> Self {
        Self {
            cb_type: CallbackType::DeferredWork,
            arg: 0,
            generation: 0,
            occupied: false,
            seq: 0,
        }
    }

    /// Creates a new callback entry.
    pub fn with_values(cb_type: CallbackType, arg: u64, generation: u64, seq: u64) -> Self {
        Self {
            cb_type,
            arg,
            generation,
            occupied: true,
            seq,
        }
    }

    /// Returns the callback type.
    pub fn cb_type(&self) -> CallbackType {
        self.cb_type
    }

    /// Returns the argument.
    pub fn arg(&self) -> u64 {
        self.arg
    }

    /// Returns the generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns whether this entry is occupied.
    pub fn is_occupied(&self) -> bool {
        self.occupied
    }
}

// ======================================================================
// Callback segment
// ======================================================================

/// A single segment in the segmented callback list.
pub struct CallbackSegment {
    /// Callback entries in this segment.
    entries: [RcuCallbackEntry; MAX_CBS_PER_SEGMENT],
    /// Number of occupied entries.
    count: usize,
    /// Grace period number this segment is associated with.
    gp_num: u64,
}

impl CallbackSegment {
    /// Creates an empty segment.
    pub const fn new() -> Self {
        Self {
            entries: [const { RcuCallbackEntry::new() }; MAX_CBS_PER_SEGMENT],
            count: 0,
            gp_num: 0,
        }
    }

    /// Returns the number of callbacks.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns the associated grace period number.
    pub fn gp_num(&self) -> u64 {
        self.gp_num
    }

    /// Returns whether the segment is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns whether the segment is full.
    pub fn is_full(&self) -> bool {
        self.count >= MAX_CBS_PER_SEGMENT
    }

    /// Enqueues a callback.
    pub fn enqueue(&mut self, entry: RcuCallbackEntry) -> Result<()> {
        if self.is_full() {
            return Err(Error::OutOfMemory);
        }
        let slot = self
            .entries
            .iter()
            .position(|e| !e.occupied)
            .ok_or(Error::OutOfMemory)?;
        self.entries[slot] = entry;
        self.count += 1;
        Ok(())
    }

    /// Dequeues up to `limit` callbacks, returning the count
    /// dequeued. The dequeued entries are written to `out`.
    pub fn dequeue_batch(&mut self, out: &mut [RcuCallbackEntry], limit: usize) -> usize {
        let mut dequeued = 0;
        let max = limit.min(out.len());
        for entry in &mut self.entries {
            if dequeued >= max {
                break;
            }
            if entry.occupied {
                out[dequeued] = *entry;
                entry.occupied = false;
                dequeued += 1;
            }
        }
        self.count = self.count.saturating_sub(dequeued);
        dequeued
    }

    /// Clears all entries.
    pub fn clear(&mut self) {
        for entry in &mut self.entries {
            entry.occupied = false;
        }
        self.count = 0;
    }
}

// ======================================================================
// Segmented callback list
// ======================================================================

/// Segmented callback list for a single CPU.
pub struct RcuSegCbList {
    /// The four segments.
    segments: [CallbackSegment; NUM_SEGMENTS],
    /// Total callback count across all segments.
    total_count: usize,
    /// Next sequence number for new callbacks.
    next_seq: u64,
    /// Whether this list is enabled.
    enabled: bool,
    /// Number of callbacks invoked.
    invoked_count: u64,
    /// Number of callbacks dropped (enqueue failures).
    dropped_count: u64,
}

impl RcuSegCbList {
    /// Creates an empty segmented callback list.
    pub const fn new() -> Self {
        Self {
            segments: [const { CallbackSegment::new() }; NUM_SEGMENTS],
            total_count: 0,
            next_seq: 1,
            enabled: true,
            invoked_count: 0,
            dropped_count: 0,
        }
    }

    /// Returns the total callback count.
    pub fn total_count(&self) -> usize {
        self.total_count
    }

    /// Returns whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.total_count == 0
    }

    /// Returns the number of callbacks invoked.
    pub fn invoked_count(&self) -> u64 {
        self.invoked_count
    }

    /// Returns the number of callbacks dropped.
    pub fn dropped_count(&self) -> u64 {
        self.dropped_count
    }

    /// Returns the count in a specific segment.
    pub fn segment_count(&self, seg: usize) -> usize {
        if seg < NUM_SEGMENTS {
            self.segments[seg].count()
        } else {
            0
        }
    }

    /// Returns whether there are callbacks ready to invoke.
    pub fn has_ready(&self) -> bool {
        !self.segments[SEG_DONE].is_empty()
    }

    /// Enqueues a new callback (goes into NEXT segment).
    pub fn enqueue(&mut self, cb_type: CallbackType, arg: u64, generation: u64) -> Result<()> {
        if !self.enabled {
            return Err(Error::PermissionDenied);
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let entry = RcuCallbackEntry::with_values(cb_type, arg, generation, seq);
        match self.segments[SEG_NEXT].enqueue(entry) {
            Ok(()) => {
                self.total_count += 1;
                Ok(())
            }
            Err(e) => {
                self.dropped_count = self.dropped_count.saturating_add(1);
                Err(e)
            }
        }
    }

    /// Advances segments after a grace period completes.
    ///
    /// WAIT → DONE, NEXT_READY → WAIT, NEXT → NEXT_READY.
    pub fn advance(&mut self, completed_gp: u64) {
        // Move WAIT callbacks to DONE (they are now safe to invoke).
        self.move_segment(SEG_WAIT, SEG_DONE);
        // Move NEXT_READY to WAIT.
        self.segments[SEG_WAIT].gp_num = self.segments[SEG_NEXT_READY].gp_num;
        self.move_segment(SEG_NEXT_READY, SEG_WAIT);
        // Move NEXT to NEXT_READY and assign the next GP number.
        self.segments[SEG_NEXT_READY].gp_num = completed_gp.wrapping_add(1);
        self.move_segment(SEG_NEXT, SEG_NEXT_READY);
    }

    /// Invokes ready callbacks (from DONE segment).
    /// Returns the number of callbacks invoked.
    pub fn invoke(&mut self) -> usize {
        let mut batch = [RcuCallbackEntry::new(); INVOKE_BATCH_LIMIT];
        let count = self.segments[SEG_DONE].dequeue_batch(&mut batch, INVOKE_BATCH_LIMIT);
        self.total_count = self.total_count.saturating_sub(count);
        self.invoked_count = self.invoked_count.saturating_add(count as u64);
        // In a real kernel, we'd call the actual callback functions
        // here. In this implementation, we just count them.
        count
    }

    /// Enables the callback list.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disables the callback list.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Moves all entries from `src` segment into `dst` segment.
    fn move_segment(&mut self, src: usize, dst: usize) {
        if src >= NUM_SEGMENTS || dst >= NUM_SEGMENTS || src == dst {
            return;
        }
        let mut batch = [RcuCallbackEntry::new(); MAX_CBS_PER_SEGMENT];
        let count = self.segments[src].dequeue_batch(&mut batch, MAX_CBS_PER_SEGMENT);
        for i in 0..count {
            // Best effort — drop if destination is full.
            let _ = self.segments[dst].enqueue(batch[i]);
        }
    }
}

// ======================================================================
// Grace period detector
// ======================================================================

/// Tracks grace period state.
#[derive(Debug, Clone, Copy)]
pub struct GracePeriodState {
    /// Current grace period number.
    current_gp: u64,
    /// Completed grace period number.
    completed_gp: u64,
    /// Quiescent state bitmask (one bit per CPU).
    qs_mask: u64,
    /// Required quiescent state mask (CPUs that must report).
    required_mask: u64,
    /// Whether a grace period is in progress.
    in_progress: bool,
    /// Timestamp when the current GP started (ns).
    start_ns: u64,
}

impl GracePeriodState {
    /// Creates initial grace period state.
    pub const fn new() -> Self {
        Self {
            current_gp: 0,
            completed_gp: 0,
            qs_mask: 0,
            required_mask: 0,
            in_progress: false,
            start_ns: 0,
        }
    }

    /// Returns the current GP number.
    pub fn current_gp(&self) -> u64 {
        self.current_gp
    }

    /// Returns the completed GP number.
    pub fn completed_gp(&self) -> u64 {
        self.completed_gp
    }

    /// Returns whether a GP is in progress.
    pub fn is_in_progress(&self) -> bool {
        self.in_progress
    }

    /// Starts a new grace period.
    pub fn start(&mut self, now_ns: u64, nr_cpus: u32) {
        self.current_gp = self.current_gp.wrapping_add(1);
        self.qs_mask = 0;
        self.required_mask = (1u64 << nr_cpus.min(64)) - 1;
        self.in_progress = true;
        self.start_ns = now_ns;
    }

    /// Reports a quiescent state from a CPU.
    pub fn report_qs(&mut self, cpu: u32) -> bool {
        if cpu >= 64 {
            return false;
        }
        self.qs_mask |= 1u64 << cpu;
        self.check_completion()
    }

    /// Checks whether the grace period is complete.
    fn check_completion(&mut self) -> bool {
        if self.in_progress && (self.qs_mask & self.required_mask) == self.required_mask {
            self.completed_gp = self.current_gp;
            self.in_progress = false;
            return true;
        }
        false
    }
}

// ======================================================================
// RCU callback manager
// ======================================================================

/// Global RCU callback manager.
pub struct RcuCallbackManager {
    /// Per-CPU callback lists.
    per_cpu: [RcuSegCbList; MAX_CPUS],
    /// Grace period state.
    gp_state: GracePeriodState,
    /// Number of online CPUs.
    nr_cpus: u32,
    /// Whether the manager is initialized.
    initialized: bool,
    /// Total callbacks enqueued across all CPUs.
    total_enqueued: u64,
    /// Total callbacks invoked across all CPUs.
    total_invoked: u64,
}

impl RcuCallbackManager {
    /// Creates a new RCU callback manager.
    pub const fn new() -> Self {
        Self {
            per_cpu: [const { RcuSegCbList::new() }; MAX_CPUS],
            gp_state: GracePeriodState::new(),
            nr_cpus: 0,
            initialized: false,
            total_enqueued: 0,
            total_invoked: 0,
        }
    }

    /// Initializes the manager with the number of CPUs.
    pub fn init(&mut self, nr_cpus: u32) -> Result<()> {
        if nr_cpus == 0 || nr_cpus as usize > MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.nr_cpus = nr_cpus;
        self.initialized = true;
        Ok(())
    }

    /// Returns the grace period state.
    pub fn gp_state(&self) -> &GracePeriodState {
        &self.gp_state
    }

    /// Returns the total enqueued count.
    pub fn total_enqueued(&self) -> u64 {
        self.total_enqueued
    }

    /// Returns the total invoked count.
    pub fn total_invoked(&self) -> u64 {
        self.total_invoked
    }

    /// Enqueues a callback on a specific CPU.
    pub fn call_rcu(&mut self, cpu: u32, cb_type: CallbackType, arg: u64) -> Result<()> {
        if !self.initialized {
            return Err(Error::NotImplemented);
        }
        if cpu as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let gp = self.gp_state.current_gp;
        self.per_cpu[cpu as usize].enqueue(cb_type, arg, gp)?;
        self.total_enqueued = self.total_enqueued.saturating_add(1);
        // Start a new GP if none is in progress.
        if !self.gp_state.in_progress {
            self.gp_state.start(0, self.nr_cpus);
        }
        Ok(())
    }

    /// Reports a quiescent state from a CPU.
    pub fn report_qs(&mut self, cpu: u32) -> Result<bool> {
        if !self.initialized {
            return Err(Error::NotImplemented);
        }
        let completed = self.gp_state.report_qs(cpu);
        if completed {
            // Advance all per-CPU callback lists.
            let completed_gp = self.gp_state.completed_gp;
            for i in 0..self.nr_cpus as usize {
                self.per_cpu[i].advance(completed_gp);
            }
        }
        Ok(completed)
    }

    /// Invokes ready callbacks on a specific CPU.
    pub fn invoke_callbacks(&mut self, cpu: u32) -> Result<usize> {
        if !self.initialized {
            return Err(Error::NotImplemented);
        }
        if cpu as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let count = self.per_cpu[cpu as usize].invoke();
        self.total_invoked = self.total_invoked.saturating_add(count as u64);
        Ok(count)
    }

    /// Returns the callback count for a specific CPU.
    pub fn cpu_cb_count(&self, cpu: u32) -> usize {
        if cpu as usize >= MAX_CPUS {
            return 0;
        }
        self.per_cpu[cpu as usize].total_count()
    }

    /// Returns whether any CPU has ready callbacks.
    pub fn has_ready_callbacks(&self) -> bool {
        for i in 0..self.nr_cpus as usize {
            if self.per_cpu[i].has_ready() {
                return true;
            }
        }
        false
    }
}
