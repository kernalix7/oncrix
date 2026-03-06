// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DMA fence memory management.
//!
//! DMA operations proceed asynchronously on hardware. A DMA fence
//! represents the completion point of a DMA transfer. Memory backing
//! a DMA transfer must remain pinned and mapped until the fence
//! signals completion. This module tracks DMA fences, their associated
//! memory regions, and provides the wait/signal mechanism.
//!
//! # Design
//!
//! ```text
//!  dma_map_single(buf, len)
//!       → DmaFenceTracker::create_fence(addr, len)
//!       → return fence_id
//!
//!  hardware completes DMA
//!       → DmaFenceTracker::signal(fence_id)
//!       → release pinned memory
//!
//!  driver waits:
//!       → DmaFenceTracker::wait(fence_id)
//! ```
//!
//! # Key Types
//!
//! - [`DmaFenceState`] — fence state machine
//! - [`DmaFence`] — a single DMA fence
//! - [`DmaFenceTracker`] — manages all active fences
//! - [`DmaFenceStats`] — fence statistics
//!
//! Reference: Linux `drivers/dma-buf/dma-fence.c`,
//! `include/linux/dma-fence.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum active fences.
const MAX_FENCES: usize = 256;

/// Maximum fence timeout (ticks).
const DEFAULT_TIMEOUT: u64 = 10_000;

/// Fence context counter initial value.
const INITIAL_SEQNO: u64 = 1;

// -------------------------------------------------------------------
// DmaFenceState
// -------------------------------------------------------------------

/// State of a DMA fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaFenceState {
    /// Fence has been created but DMA not yet started.
    Pending,
    /// DMA transfer is in progress.
    Active,
    /// DMA transfer completed successfully.
    Signaled,
    /// DMA transfer failed or timed out.
    Error,
}

impl DmaFenceState {
    /// Return a label.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Signaled => "signaled",
            Self::Error => "error",
        }
    }

    /// Check whether the fence is done (signaled or error).
    pub const fn is_done(&self) -> bool {
        matches!(self, Self::Signaled | Self::Error)
    }
}

// -------------------------------------------------------------------
// DmaFence
// -------------------------------------------------------------------

/// A single DMA fence.
#[derive(Debug, Clone, Copy)]
pub struct DmaFence {
    /// Fence identifier.
    fence_id: u64,
    /// Sequence number within the context.
    seqno: u64,
    /// DMA buffer physical address.
    phys_addr: u64,
    /// DMA buffer size in bytes.
    size: u64,
    /// Current state.
    state: DmaFenceState,
    /// Timeout in ticks.
    timeout: u64,
    /// Elapsed ticks since creation.
    elapsed: u64,
    /// Number of waiters.
    waiter_count: u32,
}

impl DmaFence {
    /// Create a new fence.
    pub const fn new(fence_id: u64, seqno: u64, phys_addr: u64, size: u64) -> Self {
        Self {
            fence_id,
            seqno,
            phys_addr,
            size,
            state: DmaFenceState::Pending,
            timeout: DEFAULT_TIMEOUT,
            elapsed: 0,
            waiter_count: 0,
        }
    }

    /// Return the fence identifier.
    pub const fn fence_id(&self) -> u64 {
        self.fence_id
    }

    /// Return the sequence number.
    pub const fn seqno(&self) -> u64 {
        self.seqno
    }

    /// Return the physical address.
    pub const fn phys_addr(&self) -> u64 {
        self.phys_addr
    }

    /// Return the buffer size.
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Return the current state.
    pub const fn state(&self) -> DmaFenceState {
        self.state
    }

    /// Return the number of waiters.
    pub const fn waiter_count(&self) -> u32 {
        self.waiter_count
    }

    /// Check whether the fence is signaled.
    pub const fn is_signaled(&self) -> bool {
        matches!(self.state, DmaFenceState::Signaled)
    }

    /// Check whether the fence is done.
    pub const fn is_done(&self) -> bool {
        self.state.is_done()
    }

    /// Check whether the fence has timed out.
    pub const fn is_timed_out(&self) -> bool {
        self.elapsed >= self.timeout
    }

    /// Activate the fence (DMA started).
    pub fn activate(&mut self) -> Result<()> {
        if self.state != DmaFenceState::Pending {
            return Err(Error::InvalidArgument);
        }
        self.state = DmaFenceState::Active;
        Ok(())
    }

    /// Signal the fence (DMA completed).
    pub fn signal(&mut self) -> Result<()> {
        if self.state.is_done() {
            return Err(Error::InvalidArgument);
        }
        self.state = DmaFenceState::Signaled;
        Ok(())
    }

    /// Set the fence to error state.
    pub fn set_error(&mut self) {
        self.state = DmaFenceState::Error;
    }

    /// Add a waiter.
    pub fn add_waiter(&mut self) {
        self.waiter_count = self.waiter_count.saturating_add(1);
    }

    /// Remove a waiter.
    pub fn remove_waiter(&mut self) {
        self.waiter_count = self.waiter_count.saturating_sub(1);
    }

    /// Advance the elapsed timer. Returns true if timed out.
    pub fn tick(&mut self, ticks: u64) -> bool {
        self.elapsed += ticks;
        if !self.state.is_done() && self.is_timed_out() {
            self.state = DmaFenceState::Error;
            return true;
        }
        false
    }
}

impl Default for DmaFence {
    fn default() -> Self {
        Self {
            fence_id: 0,
            seqno: 0,
            phys_addr: 0,
            size: 0,
            state: DmaFenceState::Signaled,
            timeout: 0,
            elapsed: 0,
            waiter_count: 0,
        }
    }
}

// -------------------------------------------------------------------
// DmaFenceStats
// -------------------------------------------------------------------

/// Fence statistics.
#[derive(Debug, Clone, Copy)]
pub struct DmaFenceStats {
    /// Total fences created.
    pub created: u64,
    /// Total fences signaled.
    pub signaled: u64,
    /// Total fences timed out.
    pub timed_out: u64,
    /// Total fences errored.
    pub errored: u64,
    /// Currently active fences.
    pub active: u64,
}

impl DmaFenceStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            created: 0,
            signaled: 0,
            timed_out: 0,
            errored: 0,
            active: 0,
        }
    }
}

impl Default for DmaFenceStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// DmaFenceTracker
// -------------------------------------------------------------------

/// Manages all active DMA fences.
pub struct DmaFenceTracker {
    /// Active fences.
    fences: [DmaFence; MAX_FENCES],
    /// Number of valid entries.
    count: usize,
    /// Next fence identifier.
    next_id: u64,
    /// Next sequence number.
    next_seqno: u64,
    /// Statistics.
    stats: DmaFenceStats,
}

impl DmaFenceTracker {
    /// Create a new tracker.
    pub const fn new() -> Self {
        Self {
            fences: [const {
                DmaFence {
                    fence_id: 0,
                    seqno: 0,
                    phys_addr: 0,
                    size: 0,
                    state: DmaFenceState::Signaled,
                    timeout: 0,
                    elapsed: 0,
                    waiter_count: 0,
                }
            }; MAX_FENCES],
            count: 0,
            next_id: 1,
            next_seqno: INITIAL_SEQNO,
            stats: DmaFenceStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &DmaFenceStats {
        &self.stats
    }

    /// Return the number of tracked fences.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Create a new fence.
    pub fn create(&mut self, phys_addr: u64, size: u64) -> Result<u64> {
        if self.count >= MAX_FENCES {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_id;
        self.next_id += 1;
        let seqno = self.next_seqno;
        self.next_seqno += 1;

        let fence = DmaFence::new(id, seqno, phys_addr, size);
        self.fences[self.count] = fence;
        self.count += 1;
        self.stats.created += 1;
        self.stats.active += 1;
        Ok(id)
    }

    /// Signal a fence by ID.
    pub fn signal(&mut self, fence_id: u64) -> Result<()> {
        for idx in 0..self.count {
            if self.fences[idx].fence_id() == fence_id {
                self.fences[idx].signal()?;
                self.stats.signaled += 1;
                self.stats.active = self.stats.active.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Check whether a fence is signaled.
    pub fn is_signaled(&self, fence_id: u64) -> bool {
        for idx in 0..self.count {
            if self.fences[idx].fence_id() == fence_id {
                return self.fences[idx].is_signaled();
            }
        }
        false
    }

    /// Tick all fences forward.
    pub fn tick_all(&mut self, ticks: u64) {
        for idx in 0..self.count {
            if !self.fences[idx].is_done() && self.fences[idx].tick(ticks) {
                self.stats.timed_out += 1;
                self.stats.active = self.stats.active.saturating_sub(1);
            }
        }
    }

    /// Find a fence by ID.
    pub fn find(&self, fence_id: u64) -> Option<&DmaFence> {
        for idx in 0..self.count {
            if self.fences[idx].fence_id() == fence_id {
                return Some(&self.fences[idx]);
            }
        }
        None
    }
}

impl Default for DmaFenceTracker {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Wait for a fence to signal (returns immediately in this stub).
pub fn fence_wait(tracker: &DmaFenceTracker, fence_id: u64) -> Result<()> {
    match tracker.find(fence_id) {
        Some(f) if f.is_signaled() => Ok(()),
        Some(f) if f.is_done() => Err(Error::IoError),
        Some(_) => Err(Error::WouldBlock),
        None => Err(Error::NotFound),
    }
}

/// Return the number of active (unsignaled) fences.
pub const fn active_fence_count(tracker: &DmaFenceTracker) -> u64 {
    tracker.stats().active
}

/// Return the default fence timeout.
pub const fn default_timeout() -> u64 {
    DEFAULT_TIMEOUT
}
