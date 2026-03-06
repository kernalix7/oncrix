// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RCU synchronization primitives.
//!
//! Provides synchronization mechanisms built on Read-Copy-Update,
//! including rcu_sync (optimized reader/writer synchronization),
//! SRCU-like sleepable variants, and RCU-protected pointer updates.
//! These primitives allow readers to proceed without locks while
//! writers synchronize via grace period completion.

use oncrix_lib::{Error, Result};

/// Maximum number of RCU sync objects.
const MAX_RCU_SYNC: usize = 128;

/// Maximum number of pending callbacks.
const MAX_PENDING_CBS: usize = 512;

/// RCU sync state machine states.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RcuSyncState {
    /// Idle — no writer active, readers use fast path.
    Idle,
    /// A writer has entered, readers must use slow path.
    Active,
    /// Grace period in progress for writer exit.
    GracePeriod,
    /// Transitioning back to idle after grace period.
    Draining,
}

/// RCU synchronization object.
///
/// Optimizes the common case where writers are rare. When no
/// writer is active, readers take a fast path with no
/// synchronization overhead.
#[derive(Clone, Copy)]
pub struct RcuSync {
    /// Unique identifier for this sync object.
    id: u32,
    /// Current state.
    state: RcuSyncState,
    /// Number of active readers in slow path.
    slow_readers: u64,
    /// Grace period sequence number.
    gp_seq: u64,
    /// Number of writers waiting.
    pending_writers: u32,
    /// Whether this sync object is initialized.
    initialized: bool,
}

impl RcuSync {
    /// Creates a new RCU sync object.
    pub const fn new() -> Self {
        Self {
            id: 0,
            state: RcuSyncState::Idle,
            slow_readers: 0,
            gp_seq: 0,
            pending_writers: 0,
            initialized: false,
        }
    }

    /// Initializes the RCU sync object with an ID.
    pub fn init(&mut self, id: u32) {
        self.id = id;
        self.state = RcuSyncState::Idle;
        self.slow_readers = 0;
        self.gp_seq = 0;
        self.pending_writers = 0;
        self.initialized = true;
    }

    /// Returns whether this sync object is initialized.
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns the current state.
    pub const fn state(&self) -> RcuSyncState {
        self.state
    }

    /// Returns whether a writer is active (readers must slow-path).
    pub const fn is_writer_active(&self) -> bool {
        matches!(self.state, RcuSyncState::Active | RcuSyncState::GracePeriod)
    }

    /// Enter the read-side critical section.
    pub fn read_enter(&mut self) -> Result<()> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        if self.is_writer_active() {
            self.slow_readers += 1;
        }
        Ok(())
    }

    /// Exit the read-side critical section.
    pub fn read_exit(&mut self) -> Result<()> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        if self.is_writer_active() && self.slow_readers > 0 {
            self.slow_readers -= 1;
        }
        Ok(())
    }

    /// Enter the write-side critical section.
    pub fn write_enter(&mut self) -> Result<()> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        self.pending_writers += 1;
        self.state = RcuSyncState::Active;
        Ok(())
    }

    /// Exit the write-side critical section.
    pub fn write_exit(&mut self) -> Result<()> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        if self.pending_writers == 0 {
            return Err(Error::InvalidArgument);
        }
        self.pending_writers -= 1;
        if self.pending_writers == 0 {
            self.state = RcuSyncState::GracePeriod;
            self.gp_seq += 1;
        }
        Ok(())
    }

    /// Complete the grace period and return to idle.
    pub fn complete_grace_period(&mut self) -> Result<()> {
        if self.state != RcuSyncState::GracePeriod {
            return Err(Error::InvalidArgument);
        }
        if self.slow_readers > 0 {
            return Err(Error::Busy);
        }
        self.state = RcuSyncState::Idle;
        Ok(())
    }

    /// Returns the current grace period sequence number.
    pub const fn gp_seq(&self) -> u64 {
        self.gp_seq
    }
}

impl Default for RcuSync {
    fn default() -> Self {
        Self::new()
    }
}

/// RCU callback entry for deferred work.
#[derive(Clone, Copy)]
pub struct RcuCallback {
    /// Callback identifier.
    id: u64,
    /// Grace period number this callback waits for.
    target_gp: u64,
    /// Data pointer associated with the callback.
    data_ptr: u64,
    /// Whether this callback has been executed.
    executed: bool,
}

impl RcuCallback {
    /// Creates a new RCU callback.
    pub const fn new() -> Self {
        Self {
            id: 0,
            target_gp: 0,
            data_ptr: 0,
            executed: false,
        }
    }

    /// Creates a callback targeting a specific grace period.
    pub const fn with_target(id: u64, target_gp: u64, data_ptr: u64) -> Self {
        Self {
            id,
            target_gp,
            data_ptr,
            executed: false,
        }
    }

    /// Returns the callback identifier.
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Returns whether this callback has been executed.
    pub const fn is_executed(&self) -> bool {
        self.executed
    }

    /// Returns the target grace period.
    pub const fn target_gp(&self) -> u64 {
        self.target_gp
    }
}

impl Default for RcuCallback {
    fn default() -> Self {
        Self::new()
    }
}

/// RCU synchronization manager.
pub struct RcuSyncManager {
    /// Registered sync objects.
    syncs: [RcuSync; MAX_RCU_SYNC],
    /// Number of active sync objects.
    sync_count: usize,
    /// Pending callbacks.
    callbacks: [RcuCallback; MAX_PENDING_CBS],
    /// Number of pending callbacks.
    cb_count: usize,
    /// Next callback ID.
    next_cb_id: u64,
    /// Global grace period counter.
    global_gp: u64,
}

impl RcuSyncManager {
    /// Creates a new RCU sync manager.
    pub const fn new() -> Self {
        Self {
            syncs: [const { RcuSync::new() }; MAX_RCU_SYNC],
            sync_count: 0,
            callbacks: [const { RcuCallback::new() }; MAX_PENDING_CBS],
            cb_count: 0,
            next_cb_id: 1,
            global_gp: 0,
        }
    }

    /// Allocates and initializes a new RCU sync object.
    pub fn alloc_sync(&mut self) -> Result<u32> {
        if self.sync_count >= MAX_RCU_SYNC {
            return Err(Error::OutOfMemory);
        }
        let id = self.sync_count as u32;
        self.syncs[self.sync_count].init(id);
        self.sync_count += 1;
        Ok(id)
    }

    /// Returns a reference to a sync object by ID.
    pub fn get_sync(&self, id: u32) -> Result<&RcuSync> {
        let idx = id as usize;
        if idx >= self.sync_count {
            return Err(Error::NotFound);
        }
        Ok(&self.syncs[idx])
    }

    /// Returns a mutable reference to a sync object by ID.
    pub fn get_sync_mut(&mut self, id: u32) -> Result<&mut RcuSync> {
        let idx = id as usize;
        if idx >= self.sync_count {
            return Err(Error::NotFound);
        }
        Ok(&mut self.syncs[idx])
    }

    /// Queues a callback to execute after the next grace period.
    pub fn queue_callback(&mut self, data_ptr: u64) -> Result<u64> {
        if self.cb_count >= MAX_PENDING_CBS {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_cb_id;
        self.next_cb_id += 1;
        self.callbacks[self.cb_count] = RcuCallback::with_target(id, self.global_gp + 1, data_ptr);
        self.cb_count += 1;
        Ok(id)
    }

    /// Advances the global grace period and processes callbacks.
    pub fn advance_grace_period(&mut self) -> usize {
        self.global_gp += 1;
        let mut executed = 0usize;

        for i in 0..self.cb_count {
            if !self.callbacks[i].executed && self.callbacks[i].target_gp <= self.global_gp {
                self.callbacks[i].executed = true;
                executed += 1;
            }
        }

        // Complete grace periods on all sync objects
        for i in 0..self.sync_count {
            if self.syncs[i].state == RcuSyncState::GracePeriod && self.syncs[i].slow_readers == 0 {
                self.syncs[i].state = RcuSyncState::Idle;
            }
        }

        executed
    }

    /// Returns the number of pending (unexecuted) callbacks.
    pub fn pending_callbacks(&self) -> usize {
        let mut pending = 0usize;
        for i in 0..self.cb_count {
            if !self.callbacks[i].executed {
                pending += 1;
            }
        }
        pending
    }

    /// Returns the global grace period counter.
    pub const fn global_gp(&self) -> u64 {
        self.global_gp
    }

    /// Returns the number of active sync objects.
    pub const fn sync_count(&self) -> usize {
        self.sync_count
    }
}

impl Default for RcuSyncManager {
    fn default() -> Self {
        Self::new()
    }
}
