// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DMA fence synchronization primitives.
//!
//! Provides GPU/DMA buffer synchronization through fences and timelines,
//! modelled after the Linux `dma-fence` framework. Fences are signalling
//! objects attached to GPU work items; waiters block (or poll) until a
//! fence is signalled by the producing hardware context.
//!
//! # Architecture
//!
//! - [`FenceState`] — lifecycle of a fence (Unsignaled / Signaled / Error)
//! - [`FenceFlags`] — optional fence behaviour modifiers
//! - [`DmaFence`] — the core signalling primitive
//! - [`FenceWaiter`] — a registered wait on a specific fence
//! - [`FenceTimeline`] — ordered sequence of fences for a context (e.g., GPU ring)
//! - [`DmaFenceSubsystem`] — system-wide fence/timeline/waiter registry
//!
//! # Usage
//!
//! ```ignore
//! let mut subsys = DmaFenceSubsystem::new();
//! let ctx = subsys.create_timeline()?;
//! let fence_id = subsys.create_fence(ctx, 1, 0)?;
//! subsys.signal(fence_id, 42)?;
//! assert!(subsys.is_signaled(fence_id)?);
//! ```
//!
//! Reference: Linux `include/linux/dma-fence.h`, `drivers/dma-buf/dma-fence.c`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of fences in the subsystem.
const MAX_FENCES: usize = 128;

/// Maximum number of timelines.
const MAX_TIMELINES: usize = 32;

/// Maximum number of fence waiters.
const MAX_WAITERS: usize = 64;

/// Maximum number of pending fences per timeline.
const MAX_PENDING_PER_TIMELINE: usize = 64;

/// Sentinel value for an invalid/unused fence ID.
const INVALID_FENCE_ID: u32 = u32::MAX;

// ---------------------------------------------------------------------------
// FenceState
// ---------------------------------------------------------------------------

/// Lifecycle state of a DMA fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FenceState {
    /// The fence has not yet been signaled.
    #[default]
    Unsignaled,
    /// The fence has been signaled — the associated work is complete.
    Signaled,
    /// The fence was signaled with an error condition.
    Error,
}

// ---------------------------------------------------------------------------
// FenceFlags
// ---------------------------------------------------------------------------

/// Modifiers that alter fence behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FenceFlags(u32);

impl FenceFlags {
    /// No special behaviour.
    pub const NONE: Self = Self(0);
    /// Fence is already in the signaled state at creation.
    pub const SIGNALED: Self = Self(1 << 0);
    /// Fence belongs to a timeline (ordered sequence).
    pub const ENABLE_TIMELINE: Self = Self(1 << 1);
    /// Do not block on wait; return immediately if unsignaled.
    pub const NO_WAIT: Self = Self(1 << 2);

    /// Returns the raw bits.
    pub fn bits(self) -> u32 {
        self.0
    }

    /// Returns `true` if the SIGNALED flag is set.
    pub fn is_pre_signaled(self) -> bool {
        self.0 & Self::SIGNALED.0 != 0
    }

    /// Returns `true` if timeline ordering is requested.
    pub fn timeline_enabled(self) -> bool {
        self.0 & Self::ENABLE_TIMELINE.0 != 0
    }

    /// Returns `true` if non-blocking wait is requested.
    pub fn no_wait(self) -> bool {
        self.0 & Self::NO_WAIT.0 != 0
    }

    /// Combines two flag sets.
    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

// ---------------------------------------------------------------------------
// DmaFence
// ---------------------------------------------------------------------------

/// A DMA synchronization fence.
///
/// A fence is created in the [`FenceState::Unsignaled`] state. The
/// producing hardware or driver calls [`DmaFence::signal`] when it
/// finishes the associated GPU or DMA work. Consumers poll or wait
/// for the signal before accessing the output buffer.
#[derive(Debug)]
pub struct DmaFence {
    /// Unique fence identifier within the subsystem.
    pub id: u32,
    /// Context (GPU ring, engine) that will signal this fence.
    pub context: u64,
    /// Monotonically increasing sequence number within the context.
    pub seqno: u64,
    /// Behaviour flags.
    pub flags: FenceFlags,
    /// Current lifecycle state.
    pub state: FenceState,
    /// Tick counter at fence creation.
    pub timestamp_tick: u64,
    /// Tick counter at signaling (0 = not yet signaled).
    pub signal_tick: u64,
    /// Error code when `state == Error` (0 = no error).
    pub error_code: i32,
}

impl Default for DmaFence {
    fn default() -> Self {
        Self::new()
    }
}

impl DmaFence {
    /// Creates a zeroed, unsignaled fence.
    pub const fn new() -> Self {
        Self {
            id: INVALID_FENCE_ID,
            context: 0,
            seqno: 0,
            flags: FenceFlags::NONE,
            state: FenceState::Unsignaled,
            timestamp_tick: 0,
            signal_tick: 0,
            error_code: 0,
        }
    }

    /// Creates a fence for a given context and sequence number.
    pub fn with_context(id: u32, context: u64, seqno: u64, flags: FenceFlags, now: u64) -> Self {
        let state = if flags.is_pre_signaled() {
            FenceState::Signaled
        } else {
            FenceState::Unsignaled
        };
        Self {
            id,
            context,
            seqno,
            flags,
            state,
            timestamp_tick: now,
            signal_tick: if flags.is_pre_signaled() { now } else { 0 },
            error_code: 0,
        }
    }

    /// Returns `true` if this fence slot is unused.
    pub fn is_empty(&self) -> bool {
        self.id == INVALID_FENCE_ID
    }

    /// Returns `true` if this fence has been signaled (successfully or with error).
    pub fn is_signaled(&self) -> bool {
        self.state == FenceState::Signaled || self.state == FenceState::Error
    }

    /// Signals the fence successfully at the given tick.
    pub fn signal(&mut self, tick: u64) {
        if self.state == FenceState::Unsignaled {
            self.state = FenceState::Signaled;
            self.signal_tick = tick;
        }
    }

    /// Signals the fence with an error at the given tick.
    pub fn signal_error(&mut self, tick: u64, error_code: i32) {
        if self.state == FenceState::Unsignaled {
            self.state = FenceState::Error;
            self.signal_tick = tick;
            self.error_code = error_code;
        }
    }

    /// Returns the current status: `Ok(())` if signaled, `Err(IoError)` on error,
    /// `Err(Busy)` if still unsignaled.
    pub fn get_status(&self) -> Result<()> {
        match self.state {
            FenceState::Signaled => Ok(()),
            FenceState::Error => Err(Error::IoError),
            FenceState::Unsignaled => Err(Error::Busy),
        }
    }

    /// Polls without blocking: returns `Ok(true)` if signaled, `Ok(false)` if pending.
    pub fn poll(&self) -> Result<bool> {
        Ok(self.is_signaled())
    }
}

// ---------------------------------------------------------------------------
// FenceWaiter
// ---------------------------------------------------------------------------

/// A registered waiter on a specific fence.
///
/// Waiters are created by consumers that need to know when a fence is
/// signaled. They carry an optional timeout and a callback index.
#[derive(Debug, Clone, Copy)]
pub struct FenceWaiter {
    /// Fence being waited upon.
    pub fence_id: u32,
    /// Index into a callback table (0 = no callback).
    pub callback_index: u32,
    /// Absolute tick at which the wait expires (0 = no timeout).
    pub timeout_ticks: u64,
    /// Whether this waiter slot is active.
    pub active: bool,
}

impl Default for FenceWaiter {
    fn default() -> Self {
        Self::new()
    }
}

impl FenceWaiter {
    /// Creates an inactive waiter slot.
    pub const fn new() -> Self {
        Self {
            fence_id: INVALID_FENCE_ID,
            callback_index: 0,
            timeout_ticks: 0,
            active: false,
        }
    }

    /// Creates an active waiter for the given fence with an optional timeout.
    pub const fn for_fence(fence_id: u32, callback_index: u32, timeout_ticks: u64) -> Self {
        Self {
            fence_id,
            callback_index,
            timeout_ticks,
            active: true,
        }
    }

    /// Returns `true` if the waiter has timed out at the given tick.
    pub fn is_expired(&self, now: u64) -> bool {
        self.timeout_ticks != 0 && now >= self.timeout_ticks
    }
}

// ---------------------------------------------------------------------------
// FenceTimeline
// ---------------------------------------------------------------------------

/// An ordered sequence of fences for a single GPU context or DMA engine.
///
/// A timeline ensures in-order signaling: fence with `seqno N` must be
/// signaled before fence with `seqno N+1` (or simultaneously). The
/// [`FenceTimeline::advance`] method signals all consecutive pending
/// fences up to and including `target_seqno`.
pub struct FenceTimeline {
    /// Unique context identifier for this timeline.
    pub context: u64,
    /// Sequence number of the last successfully signaled fence.
    pub last_signaled_seqno: u64,
    /// IDs of pending fences in creation order.
    pending_fence_ids: [u32; MAX_PENDING_PER_TIMELINE],
    /// Sequence numbers corresponding to each pending fence.
    pending_seqnos: [u64; MAX_PENDING_PER_TIMELINE],
    /// Number of entries in the pending arrays.
    pending_count: usize,
    /// Whether this timeline slot is occupied.
    pub active: bool,
}

impl Default for FenceTimeline {
    fn default() -> Self {
        Self::new()
    }
}

impl FenceTimeline {
    /// Creates an inactive, zeroed timeline.
    pub const fn new() -> Self {
        Self {
            context: 0,
            last_signaled_seqno: 0,
            pending_fence_ids: [INVALID_FENCE_ID; MAX_PENDING_PER_TIMELINE],
            pending_seqnos: [0u64; MAX_PENDING_PER_TIMELINE],
            pending_count: 0,
            active: false,
        }
    }

    /// Creates an active timeline for the given context.
    pub fn with_context(context: u64) -> Self {
        Self {
            context,
            last_signaled_seqno: 0,
            pending_fence_ids: [INVALID_FENCE_ID; MAX_PENDING_PER_TIMELINE],
            pending_seqnos: [0u64; MAX_PENDING_PER_TIMELINE],
            pending_count: 0,
            active: true,
        }
    }

    /// Registers a fence as pending on this timeline.
    pub fn add_pending(&mut self, fence_id: u32, seqno: u64) -> Result<()> {
        if self.pending_count >= MAX_PENDING_PER_TIMELINE {
            return Err(Error::OutOfMemory);
        }
        let idx = self.pending_count;
        self.pending_fence_ids[idx] = fence_id;
        self.pending_seqnos[idx] = seqno;
        self.pending_count += 1;
        Ok(())
    }

    /// Returns the IDs of fences that should be signaled to advance the
    /// timeline to `target_seqno`. The caller signals those fences.
    ///
    /// Returns up to `out.len()` fence IDs and sets `*found` to the count.
    pub fn collect_ready(&self, target_seqno: u64, out: &mut [u32]) -> usize {
        let mut found = 0;
        for i in 0..self.pending_count {
            if self.pending_seqnos[i] <= target_seqno {
                if found < out.len() {
                    out[found] = self.pending_fence_ids[i];
                    found += 1;
                }
            }
        }
        found
    }

    /// Advances the timeline, removing all pending entries with seqno ≤ target.
    pub fn advance(&mut self, target_seqno: u64) {
        let mut write = 0;
        for i in 0..self.pending_count {
            if self.pending_seqnos[i] > target_seqno {
                self.pending_fence_ids[write] = self.pending_fence_ids[i];
                self.pending_seqnos[write] = self.pending_seqnos[i];
                write += 1;
            }
        }
        // Clear tail
        for i in write..self.pending_count {
            self.pending_fence_ids[i] = INVALID_FENCE_ID;
            self.pending_seqnos[i] = 0;
        }
        self.pending_count = write;
        if target_seqno > self.last_signaled_seqno {
            self.last_signaled_seqno = target_seqno;
        }
    }

    /// Returns the number of pending (unsignaled) fences on this timeline.
    pub fn pending_count(&self) -> usize {
        self.pending_count
    }
}

// ---------------------------------------------------------------------------
// DmaFenceSubsystem
// ---------------------------------------------------------------------------

/// System-wide registry of DMA fences, timelines, and waiters.
///
/// Provides the central coordination point for GPU/DMA synchronization.
/// Fences are created here, signaled by producers, and waited upon by
/// consumers. Timelines provide ordered signaling semantics.
pub struct DmaFenceSubsystem {
    /// All allocated fences.
    fences: [DmaFence; MAX_FENCES],
    /// All allocated timelines.
    timelines: [FenceTimeline; MAX_TIMELINES],
    /// All registered waiters.
    waiters: [FenceWaiter; MAX_WAITERS],
    /// Monotonically increasing fence ID counter.
    next_fence_id: u32,
    /// Monotonically increasing context counter for timelines.
    next_context: u64,
}

impl Default for DmaFenceSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl DmaFenceSubsystem {
    /// Creates an empty fence subsystem.
    pub fn new() -> Self {
        Self {
            fences: [const { DmaFence::new() }; MAX_FENCES],
            timelines: [const { FenceTimeline::new() }; MAX_TIMELINES],
            waiters: [const { FenceWaiter::new() }; MAX_WAITERS],
            next_fence_id: 1,
            next_context: 1,
        }
    }

    // ── Fence operations ─────────────────────────────────────────────

    /// Allocates and returns a new unsignaled fence ID.
    ///
    /// `context` identifies the GPU ring/engine; `seqno` is the submission
    /// sequence number; `now` is the current tick counter.
    pub fn create_fence(
        &mut self,
        context: u64,
        seqno: u64,
        flags: FenceFlags,
        now: u64,
    ) -> Result<u32> {
        let slot = self.fences.iter().position(|f| f.is_empty());
        let idx = slot.ok_or(Error::OutOfMemory)?;
        let id = self.next_fence_id;
        self.next_fence_id = self.next_fence_id.wrapping_add(1);
        self.fences[idx] = DmaFence::with_context(id, context, seqno, flags, now);
        Ok(id)
    }

    /// Signals a fence successfully.
    pub fn signal(&mut self, fence_id: u32, tick: u64) -> Result<()> {
        let idx = self.find_fence_idx(fence_id)?;
        self.fences[idx].signal(tick);
        Ok(())
    }

    /// Signals a fence with an error.
    pub fn signal_error(&mut self, fence_id: u32, tick: u64, error_code: i32) -> Result<()> {
        let idx = self.find_fence_idx(fence_id)?;
        self.fences[idx].signal_error(tick, error_code);
        Ok(())
    }

    /// Returns `true` if the fence identified by `fence_id` has been signaled.
    pub fn is_signaled(&self, fence_id: u32) -> Result<bool> {
        let idx = self.find_fence_idx_ref(fence_id)?;
        Ok(self.fences[idx].is_signaled())
    }

    /// Returns the current status of a fence.
    pub fn get_status(&self, fence_id: u32) -> Result<()> {
        let idx = self.find_fence_idx_ref(fence_id)?;
        self.fences[idx].get_status()
    }

    /// Polls a fence without blocking.
    ///
    /// Returns `Ok(true)` if signaled, `Ok(false)` if still pending.
    pub fn poll(&self, fence_id: u32) -> Result<bool> {
        let idx = self.find_fence_idx_ref(fence_id)?;
        self.fences[idx].poll()
    }

    /// Blocking wait: returns when the fence is signaled or `now >= timeout_ticks`.
    ///
    /// Since this is a bare-metal no_std environment there is no actual thread
    /// blocking; the caller must poll in a loop. This method performs a single
    /// check and returns `Err(Busy)` if the fence is still pending and the
    /// timeout has not expired, or `Err(IoError)` on timeout.
    pub fn wait(&self, fence_id: u32, now: u64, timeout_ticks: u64) -> Result<()> {
        let idx = self.find_fence_idx_ref(fence_id)?;
        let fence = &self.fences[idx];
        if fence.is_signaled() {
            return fence.get_status();
        }
        if timeout_ticks != 0 && now >= timeout_ticks {
            return Err(Error::IoError);
        }
        Err(Error::Busy)
    }

    /// Frees a fence that is no longer needed.
    pub fn destroy_fence(&mut self, fence_id: u32) -> Result<()> {
        let idx = self.find_fence_idx(fence_id)?;
        self.fences[idx] = DmaFence::new();
        Ok(())
    }

    // ── Timeline operations ───────────────────────────────────────────

    /// Creates a new timeline, returning its context ID.
    pub fn create_timeline(&mut self) -> Result<u64> {
        let slot = self.timelines.iter().position(|t| !t.active);
        let idx = slot.ok_or(Error::OutOfMemory)?;
        let ctx = self.next_context;
        self.next_context = self.next_context.wrapping_add(1);
        self.timelines[idx] = FenceTimeline::with_context(ctx);
        Ok(ctx)
    }

    /// Creates a fence and registers it as pending on the given timeline.
    pub fn create_sync_point(&mut self, context: u64, seqno: u64, now: u64) -> Result<u32> {
        let fence_id = self.create_fence(context, seqno, FenceFlags::ENABLE_TIMELINE, now)?;
        let tl_idx = self.find_timeline_idx(context)?;
        self.timelines[tl_idx].add_pending(fence_id, seqno)?;
        Ok(fence_id)
    }

    /// Advances a timeline to `target_seqno`, signaling all fences with seqno ≤ target.
    pub fn advance_timeline(&mut self, context: u64, target_seqno: u64, tick: u64) -> Result<()> {
        let tl_idx = self.find_timeline_idx(context)?;
        // Collect fence IDs to signal
        let mut ready = [INVALID_FENCE_ID; MAX_PENDING_PER_TIMELINE];
        let count = self.timelines[tl_idx].collect_ready(target_seqno, &mut ready);
        // Signal each collected fence
        for i in 0..count {
            let fid = ready[i];
            if let Ok(fidx) = self.find_fence_idx(fid) {
                self.fences[fidx].signal(tick);
            }
        }
        self.timelines[tl_idx].advance(target_seqno);
        Ok(())
    }

    /// Destroys a timeline.
    pub fn destroy_timeline(&mut self, context: u64) -> Result<()> {
        let idx = self.find_timeline_idx(context)?;
        self.timelines[idx] = FenceTimeline::new();
        Ok(())
    }

    // ── Waiter operations ─────────────────────────────────────────────

    /// Registers a waiter for a fence, returning a waiter slot index.
    pub fn add_waiter(
        &mut self,
        fence_id: u32,
        callback_index: u32,
        timeout_ticks: u64,
    ) -> Result<usize> {
        let slot = self.waiters.iter().position(|w| !w.active);
        let idx = slot.ok_or(Error::OutOfMemory)?;
        self.waiters[idx] = FenceWaiter::for_fence(fence_id, callback_index, timeout_ticks);
        Ok(idx)
    }

    /// Removes a waiter by slot index.
    pub fn remove_waiter(&mut self, index: usize) -> Result<()> {
        if index >= MAX_WAITERS || !self.waiters[index].active {
            return Err(Error::NotFound);
        }
        self.waiters[index] = FenceWaiter::new();
        Ok(())
    }

    /// Runs the waiter expiry check at the current tick.
    ///
    /// Returns the number of waiters that timed out and were deactivated.
    pub fn check_waiters(&mut self, now: u64) -> usize {
        let mut expired = 0;
        for i in 0..MAX_WAITERS {
            if self.waiters[i].active && self.waiters[i].is_expired(now) {
                self.waiters[i] = FenceWaiter::new();
                expired += 1;
            }
        }
        expired
    }

    // ── Statistics ────────────────────────────────────────────────────

    /// Returns the number of allocated (non-empty) fences.
    pub fn fence_count(&self) -> usize {
        self.fences.iter().filter(|f| !f.is_empty()).count()
    }

    /// Returns the number of active timelines.
    pub fn timeline_count(&self) -> usize {
        self.timelines.iter().filter(|t| t.active).count()
    }

    /// Returns the number of active waiters.
    pub fn waiter_count(&self) -> usize {
        self.waiters.iter().filter(|w| w.active).count()
    }

    // ── Internal helpers ──────────────────────────────────────────────

    fn find_fence_idx(&mut self, fence_id: u32) -> Result<usize> {
        self.fences
            .iter()
            .position(|f| f.id == fence_id)
            .ok_or(Error::NotFound)
    }

    fn find_fence_idx_ref(&self, fence_id: u32) -> Result<usize> {
        self.fences
            .iter()
            .position(|f| f.id == fence_id)
            .ok_or(Error::NotFound)
    }

    fn find_timeline_idx(&mut self, context: u64) -> Result<usize> {
        self.timelines
            .iter()
            .position(|t| t.active && t.context == context)
            .ok_or(Error::NotFound)
    }
}
