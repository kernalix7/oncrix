// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! OOM reaper — background reclamation of OOM-killed process memory.
//!
//! When the Out-Of-Memory (OOM) killer selects a victim process, the
//! process may not exit immediately (it could be stuck in an
//! uninterruptible sleep, for example).  The OOM reaper runs as a
//! background kthread that proactively unmaps the victim's anonymous
//! pages so that memory is freed promptly, without waiting for the
//! victim to fully exit.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                      OomReaper                               │
//! │                                                              │
//! │  OomReaperQueue (circular buffer of victims)                 │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  victims: [OomVictim; MAX_VICTIMS]                     │  │
//! │  │  head / tail / count                                   │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  reap_one()   — unmap anonymous pages for a single victim   │
//! │  process()    — drain the queue                              │
//! │  enqueue()    — called by OOM killer to add victims          │
//! │                                                              │
//! │  OomReaperStats                                              │
//! │  - total_reaped, total_freed_pages, max_reap_time_ticks     │
//! │  - failed_count, skipped_shared, skipped_mlock              │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Skip Conditions
//!
//! The reaper skips a victim if:
//! - The victim's address space (`mm`) is shared with other live
//!   processes (we must not unmap their pages).
//! - The victim has `mlock`'d pages that must remain resident.
//!
//! # Reference
//!
//! Linux `mm/oom_kill.c` (`oom_reaper` kthread).

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum number of victims in the reaper queue.
const MAX_VICTIMS: usize = 32;

/// Maximum reap attempts before giving up on a single victim.
const MAX_REAP_ATTEMPTS: u32 = 10;

// ══════════════════════════════════════════════════════════════
// VictimState — lifecycle of a queued victim
// ══════════════════════════════════════════════════════════════

/// Lifecycle state of a victim entry in the reaper queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VictimState {
    /// Slot is unused.
    Free,
    /// Victim has been enqueued but not yet processed.
    Pending,
    /// Victim is currently being reaped.
    Reaping,
    /// Reaping completed successfully.
    Done,
    /// Reaping failed (e.g., shared mm, mlock).
    Failed,
    /// Victim was skipped due to policy.
    Skipped,
}

impl Default for VictimState {
    fn default() -> Self {
        Self::Free
    }
}

// ══════════════════════════════════════════════════════════════
// MmFlags — address space metadata
// ══════════════════════════════════════════════════════════════

/// Simplified address space flags for skip-condition checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmFlags {
    /// Number of processes sharing this mm struct.
    pub mm_users: u32,
    /// Whether any VMAs in the mm are mlock'd.
    pub has_mlock: bool,
    /// Total anonymous pages mapped.
    pub anon_pages: u64,
    /// Total file-backed pages mapped.
    pub file_pages: u64,
}

impl MmFlags {
    /// Create empty mm flags.
    pub const fn empty() -> Self {
        Self {
            mm_users: 0,
            has_mlock: false,
            anon_pages: 0,
            file_pages: 0,
        }
    }

    /// Returns `true` if the mm is shared (more than one user).
    pub const fn is_shared(&self) -> bool {
        self.mm_users > 1
    }
}

// ══════════════════════════════════════════════════════════════
// OomVictim — queued victim entry
// ══════════════════════════════════════════════════════════════

/// A single OOM victim entry in the reaper queue.
#[derive(Debug, Clone, Copy)]
pub struct OomVictim {
    /// Process ID of the victim.
    pub pid: u64,
    /// Thread group leader PID.
    pub tgid: u64,
    /// Memory descriptor identifier.
    pub mm_id: u64,
    /// Tick at which this victim was enqueued.
    pub enqueue_tick: u64,
    /// Current state in the reaping pipeline.
    pub state: VictimState,
    /// Number of reap attempts made.
    pub attempts: u32,
    /// Address space metadata for skip checks.
    pub mm_flags: MmFlags,
    /// Pages freed by the reaper for this victim.
    pub freed_pages: u64,
    /// Tick at which reaping started (0 if not started).
    pub reap_start_tick: u64,
    /// Tick at which reaping completed (0 if not done).
    pub reap_end_tick: u64,
}

impl OomVictim {
    /// Create an empty (free) victim slot.
    const fn empty() -> Self {
        Self {
            pid: 0,
            tgid: 0,
            mm_id: 0,
            enqueue_tick: 0,
            state: VictimState::Free,
            attempts: 0,
            mm_flags: MmFlags::empty(),
            freed_pages: 0,
            reap_start_tick: 0,
            reap_end_tick: 0,
        }
    }

    /// Returns `true` if this slot is free.
    pub const fn is_free(&self) -> bool {
        matches!(self.state, VictimState::Free)
    }

    /// Returns `true` if this victim is pending.
    pub const fn is_pending(&self) -> bool {
        matches!(self.state, VictimState::Pending)
    }

    /// Returns `true` if this victim was successfully reaped.
    pub const fn is_done(&self) -> bool {
        matches!(self.state, VictimState::Done)
    }
}

// ══════════════════════════════════════════════════════════════
// OomReaperQueue — circular victim buffer
// ══════════════════════════════════════════════════════════════

/// Circular buffer of OOM victims awaiting reaping.
#[derive(Debug)]
pub struct OomReaperQueue {
    /// Victim slots.
    victims: [OomVictim; MAX_VICTIMS],
    /// Index of the next victim to dequeue.
    head: usize,
    /// Index of the next free slot for enqueue.
    tail: usize,
    /// Number of victims currently queued.
    count: usize,
}

impl OomReaperQueue {
    /// Create an empty queue.
    const fn new() -> Self {
        Self {
            victims: [const { OomVictim::empty() }; MAX_VICTIMS],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    /// Returns `true` if the queue is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns `true` if the queue is full.
    pub const fn is_full(&self) -> bool {
        self.count >= MAX_VICTIMS
    }

    /// Number of queued victims.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Enqueue a new victim.
    fn enqueue(&mut self, victim: OomVictim) -> Result<()> {
        if self.is_full() {
            return Err(Error::OutOfMemory);
        }
        self.victims[self.tail] = victim;
        self.tail = (self.tail + 1) % MAX_VICTIMS;
        self.count += 1;
        Ok(())
    }

    /// Peek at the head victim without removing it.
    fn peek(&self) -> Option<&OomVictim> {
        if self.is_empty() {
            return None;
        }
        Some(&self.victims[self.head])
    }

    /// Get a mutable reference to the head victim.
    fn peek_mut(&mut self) -> Option<&mut OomVictim> {
        if self.is_empty() {
            return None;
        }
        Some(&mut self.victims[self.head])
    }

    /// Remove the head victim from the queue.
    fn dequeue(&mut self) -> Option<OomVictim> {
        if self.is_empty() {
            return None;
        }
        let victim = self.victims[self.head];
        self.victims[self.head] = OomVictim::empty();
        self.head = (self.head + 1) % MAX_VICTIMS;
        self.count -= 1;
        Some(victim)
    }
}

// ══════════════════════════════════════════════════════════════
// SkipReason — why a victim was skipped
// ══════════════════════════════════════════════════════════════

/// Reason a victim was skipped instead of reaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// The mm is shared with other live processes.
    SharedMm,
    /// The victim has mlock'd pages.
    MlockedPages,
    /// Maximum reap attempts exceeded.
    TooManyAttempts,
}

// ══════════════════════════════════════════════════════════════
// ReapResult — outcome of reaping one victim
// ══════════════════════════════════════════════════════════════

/// Outcome of attempting to reap one victim.
#[derive(Debug, Clone, Copy)]
pub enum ReapResult {
    /// Successfully reaped; number of pages freed.
    Success { freed_pages: u64 },
    /// Victim was skipped.
    Skipped(SkipReason),
    /// Queue was empty.
    QueueEmpty,
    /// Reaping failed for an internal reason.
    Failed,
}

// ══════════════════════════════════════════════════════════════
// OomReaperStats — statistics
// ══════════════════════════════════════════════════════════════

/// OOM reaper statistics.
#[derive(Debug, Clone, Copy)]
pub struct OomReaperStats {
    /// Total victims successfully reaped.
    pub total_reaped: u64,
    /// Total pages freed across all victims.
    pub total_freed_pages: u64,
    /// Maximum time (in ticks) spent reaping a single victim.
    pub max_reap_time_ticks: u64,
    /// Number of victims that failed reaping.
    pub failed_count: u64,
    /// Number of victims skipped due to shared mm.
    pub skipped_shared: u64,
    /// Number of victims skipped due to mlock.
    pub skipped_mlock: u64,
    /// Total victims enqueued.
    pub total_enqueued: u64,
}

impl OomReaperStats {
    /// Zero-initialised stats.
    const fn new() -> Self {
        Self {
            total_reaped: 0,
            total_freed_pages: 0,
            max_reap_time_ticks: 0,
            failed_count: 0,
            skipped_shared: 0,
            skipped_mlock: 0,
            total_enqueued: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// OomReaper — main reaper struct
// ══════════════════════════════════════════════════════════════

/// OOM reaper subsystem.
///
/// Manages the victim queue and provides the `reap_one` / `process`
/// interface for the oom_reaper kthread.
pub struct OomReaper {
    /// Queue of victims to reap.
    queue: OomReaperQueue,
    /// Statistics.
    stats: OomReaperStats,
    /// Whether the reaper kthread is active.
    active: bool,
    /// Whether the subsystem has been initialised.
    initialised: bool,
}

impl Default for OomReaper {
    fn default() -> Self {
        Self::new()
    }
}

impl OomReaper {
    /// Create a new, uninitialised OOM reaper.
    pub const fn new() -> Self {
        Self {
            queue: OomReaperQueue::new(),
            stats: OomReaperStats::new(),
            active: false,
            initialised: false,
        }
    }

    /// Initialise the reaper subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.active = true;
        self.initialised = true;
        Ok(())
    }

    // ── Enqueue ──────────────────────────────────────────────

    /// Enqueue a victim for reaping (called by the OOM killer).
    ///
    /// # Arguments
    ///
    /// * `pid` — victim process ID.
    /// * `tgid` — thread group leader PID.
    /// * `mm_id` — memory descriptor ID.
    /// * `mm_flags` — address space metadata.
    /// * `tick` — current tick.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` if the queue is full.
    /// - `InvalidArgument` if the reaper is not initialised.
    pub fn enqueue_victim(
        &mut self,
        pid: u64,
        tgid: u64,
        mm_id: u64,
        mm_flags: MmFlags,
        tick: u64,
    ) -> Result<()> {
        if !self.initialised {
            return Err(Error::InvalidArgument);
        }

        let victim = OomVictim {
            pid,
            tgid,
            mm_id,
            enqueue_tick: tick,
            state: VictimState::Pending,
            attempts: 0,
            mm_flags,
            freed_pages: 0,
            reap_start_tick: 0,
            reap_end_tick: 0,
        };

        self.queue.enqueue(victim)?;
        self.stats.total_enqueued += 1;
        Ok(())
    }

    // ── Reap ─────────────────────────────────────────────────

    /// Attempt to reap a single victim from the head of the queue.
    ///
    /// This is the core operation of the reaper kthread's main loop.
    pub fn reap_one(&mut self, current_tick: u64) -> ReapResult {
        // Check skip conditions on the head victim without
        // removing it yet.
        let should_skip = match self.queue.peek() {
            None => return ReapResult::QueueEmpty,
            Some(v) => self.check_skip_conditions(v),
        };

        if let Some(reason) = should_skip {
            // Mark the victim as skipped and dequeue it.
            if let Some(victim) = self.queue.peek_mut() {
                victim.state = VictimState::Skipped;
            }
            let _victim = self.queue.dequeue();
            match reason {
                SkipReason::SharedMm => self.stats.skipped_shared += 1,
                SkipReason::MlockedPages => {
                    self.stats.skipped_mlock += 1;
                }
                SkipReason::TooManyAttempts => {
                    self.stats.failed_count += 1;
                }
            }
            return ReapResult::Skipped(reason);
        }

        // Begin reaping: mark the head as Reaping.
        if let Some(victim) = self.queue.peek_mut() {
            victim.state = VictimState::Reaping;
            victim.reap_start_tick = current_tick;
            victim.attempts += 1;
        }

        // Simulate reaping: free the victim's anonymous pages.
        // In a real kernel this would walk the victim's VMA list
        // and unmap anonymous pages via `unmap_page_range()`.
        let freed = match self.queue.peek() {
            Some(v) => v.mm_flags.anon_pages,
            None => 0,
        };

        // Mark as done and dequeue.
        if let Some(victim) = self.queue.peek_mut() {
            victim.freed_pages = freed;
            victim.reap_end_tick = current_tick;
            victim.state = VictimState::Done;
        }

        let _victim = self.queue.dequeue();

        // Update stats.
        self.stats.total_reaped += 1;
        self.stats.total_freed_pages += freed;
        let elapsed = current_tick.wrapping_sub(_victim.map_or(0, |v| v.reap_start_tick));
        if elapsed > self.stats.max_reap_time_ticks {
            self.stats.max_reap_time_ticks = elapsed;
        }

        ReapResult::Success { freed_pages: freed }
    }

    /// Drain the entire queue, reaping or skipping every victim.
    ///
    /// Returns the total number of pages freed.
    pub fn process(&mut self, current_tick: u64) -> u64 {
        let mut total_freed = 0u64;
        loop {
            match self.reap_one(current_tick) {
                ReapResult::Success { freed_pages } => {
                    total_freed += freed_pages;
                }
                ReapResult::QueueEmpty => break,
                ReapResult::Skipped(_) | ReapResult::Failed => {
                    // Continue processing remaining victims.
                }
            }
        }
        total_freed
    }

    /// Check whether we should reap (returns `true` if there are
    /// pending victims in the queue).
    pub fn should_reap(&self) -> bool {
        !self.queue.is_empty()
    }

    // ── Query / diagnostics ──────────────────────────────────

    /// Return the number of victims in the queue.
    pub fn queue_len(&self) -> usize {
        self.queue.len()
    }

    /// Return `true` if the reaper kthread is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Deactivate the reaper (e.g., during shutdown).
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Return a snapshot of statistics.
    pub fn stats(&self) -> OomReaperStats {
        self.stats
    }

    /// Peek at the next victim in the queue (read-only).
    pub fn peek_next(&self) -> Option<&OomVictim> {
        self.queue.peek()
    }

    // ── Internals ────────────────────────────────────────────

    /// Check skip conditions for a victim.
    ///
    /// Returns `Some(reason)` if the victim should be skipped.
    fn check_skip_conditions(&self, victim: &OomVictim) -> Option<SkipReason> {
        // Skip if mm is shared with other live processes.
        if victim.mm_flags.is_shared() {
            return Some(SkipReason::SharedMm);
        }
        // Skip if victim has mlock'd pages.
        if victim.mm_flags.has_mlock {
            return Some(SkipReason::MlockedPages);
        }
        // Skip if we've exceeded the max attempt count.
        if victim.attempts >= MAX_REAP_ATTEMPTS {
            return Some(SkipReason::TooManyAttempts);
        }
        None
    }
}
