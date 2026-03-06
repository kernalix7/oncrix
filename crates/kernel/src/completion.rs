// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Completion synchronization primitive.
//!
//! A `Completion` is a lightweight synchronization mechanism where
//! one or more threads wait for an event to be signaled. Unlike a
//! mutex, completions are specifically designed for the "event
//! happened" pattern.
//!
//! # Usage Pattern
//!
//! ```text
//!   Thread A (waiter):          Thread B (completer):
//!   wait_for_completion(&c)     ... do work ...
//!     done == 0 → enqueue       complete(&c)
//!     sleep                       done = 1
//!     woken ←───────────────────  wake_up(queue)
//!     return
//! ```
//!
//! # complete() vs complete_all()
//!
//! - `complete()` — wakes one waiter and increments `done` by 1.
//! - `complete_all()` — sets `done` to `u32::MAX` and wakes all
//!   waiters.
//!
//! # Reference
//!
//! Linux `kernel/sched/completion.c`,
//! `include/linux/completion.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum number of waiters per completion.
const MAX_WAITERS: usize = 32;

/// Maximum number of managed completions.
const MAX_COMPLETIONS: usize = 256;

/// Value indicating "complete_all" was called.
const COMPLETION_ALL: u32 = u32::MAX;

/// Default timeout (0 = infinite).
const _DEFAULT_TIMEOUT: u64 = 0;

// ======================================================================
// Waiter state
// ======================================================================

/// State of a waiter in a completion's queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionWaiterState {
    /// Waiting for the completion.
    Waiting,
    /// Woken up (completion signaled).
    Completed,
    /// Timed out.
    TimedOut,
    /// Interrupted by a signal.
    Interrupted,
}

/// A waiter in the completion's wait queue.
#[derive(Debug, Clone, Copy)]
pub struct CompletionWaiter {
    /// Thread ID.
    tid: u32,
    /// Current state.
    state: CompletionWaiterState,
    /// Whether this slot is occupied.
    occupied: bool,
    /// Enqueue timestamp (ns).
    enqueue_ns: u64,
    /// Timeout in nanoseconds (0 = infinite).
    timeout_ns: u64,
}

impl CompletionWaiter {
    /// Creates an empty waiter.
    pub const fn new() -> Self {
        Self {
            tid: 0,
            state: CompletionWaiterState::Waiting,
            occupied: false,
            enqueue_ns: 0,
            timeout_ns: 0,
        }
    }

    /// Returns the thread ID.
    pub fn tid(&self) -> u32 {
        self.tid
    }

    /// Returns the waiter state.
    pub fn state(&self) -> CompletionWaiterState {
        self.state
    }
}

// ======================================================================
// Completion
// ======================================================================

/// A completion synchronization primitive.
pub struct Completion {
    /// Done counter. 0 = not done. >0 = number of pending
    /// completions. u32::MAX = complete_all.
    done: u32,
    /// Wait queue.
    waiters: [CompletionWaiter; MAX_WAITERS],
    /// Number of active waiters.
    nr_waiters: usize,
    /// Total number of completions signaled.
    complete_count: u64,
    /// Total number of wait operations.
    wait_count: u64,
}

impl Completion {
    /// Creates a new, not-yet-completed Completion.
    pub const fn new() -> Self {
        Self {
            done: 0,
            waiters: [const { CompletionWaiter::new() }; MAX_WAITERS],
            nr_waiters: 0,
            complete_count: 0,
            wait_count: 0,
        }
    }

    /// Creates a new already-completed Completion.
    pub const fn new_completed() -> Self {
        Self {
            done: 1,
            waiters: [const { CompletionWaiter::new() }; MAX_WAITERS],
            nr_waiters: 0,
            complete_count: 0,
            wait_count: 0,
        }
    }

    /// Returns the done counter.
    pub fn done(&self) -> u32 {
        self.done
    }

    /// Returns whether the completion has been signaled.
    pub fn is_done(&self) -> bool {
        self.done > 0
    }

    /// Returns the number of active waiters.
    pub fn nr_waiters(&self) -> usize {
        self.nr_waiters
    }

    /// Returns the total completion count.
    pub fn complete_count(&self) -> u64 {
        self.complete_count
    }

    /// Reinitializes the completion for reuse.
    pub fn reinit(&mut self) {
        self.done = 0;
        // Note: existing waiters are left untouched — they'll
        // handle the state correctly.
    }

    /// Signals one completion and wakes one waiter.
    pub fn complete(&mut self) {
        if self.done < COMPLETION_ALL {
            self.done = self.done.saturating_add(1);
        }
        self.complete_count = self.complete_count.saturating_add(1);
        // Wake one waiter.
        for waiter in &mut self.waiters {
            if waiter.occupied && waiter.state == CompletionWaiterState::Waiting {
                waiter.state = CompletionWaiterState::Completed;
                break;
            }
        }
    }

    /// Signals all waiters (sets done to MAX and wakes everyone).
    pub fn complete_all(&mut self) {
        self.done = COMPLETION_ALL;
        self.complete_count = self.complete_count.saturating_add(1);
        for waiter in &mut self.waiters {
            if waiter.occupied && waiter.state == CompletionWaiterState::Waiting {
                waiter.state = CompletionWaiterState::Completed;
            }
        }
    }

    /// Attempts to wait without blocking (non-blocking check).
    pub fn try_wait(&mut self) -> bool {
        if self.done > 0 {
            if self.done != COMPLETION_ALL {
                self.done -= 1;
            }
            true
        } else {
            false
        }
    }

    /// Waits for the completion (enqueues a waiter).
    pub fn wait_for_completion(&mut self, tid: u32, now_ns: u64) -> Result<()> {
        self.wait_count = self.wait_count.saturating_add(1);
        // If already done, consume and return immediately.
        if self.done > 0 {
            if self.done != COMPLETION_ALL {
                self.done -= 1;
            }
            return Ok(());
        }
        // Enqueue.
        let slot = self
            .waiters
            .iter()
            .position(|w| !w.occupied)
            .ok_or(Error::OutOfMemory)?;
        self.waiters[slot] = CompletionWaiter {
            tid,
            state: CompletionWaiterState::Waiting,
            occupied: true,
            enqueue_ns: now_ns,
            timeout_ns: 0,
        };
        self.nr_waiters += 1;
        Ok(())
    }

    /// Waits with a timeout (enqueues with timeout).
    pub fn wait_for_completion_timeout(
        &mut self,
        tid: u32,
        timeout_ns: u64,
        now_ns: u64,
    ) -> Result<()> {
        self.wait_count = self.wait_count.saturating_add(1);
        if self.done > 0 {
            if self.done != COMPLETION_ALL {
                self.done -= 1;
            }
            return Ok(());
        }
        let slot = self
            .waiters
            .iter()
            .position(|w| !w.occupied)
            .ok_or(Error::OutOfMemory)?;
        self.waiters[slot] = CompletionWaiter {
            tid,
            state: CompletionWaiterState::Waiting,
            occupied: true,
            enqueue_ns: now_ns,
            timeout_ns,
        };
        self.nr_waiters += 1;
        Ok(())
    }

    /// Checks timeouts and marks timed-out waiters.
    pub fn check_timeouts(&mut self, now_ns: u64) -> usize {
        let mut timed_out = 0;
        for waiter in &mut self.waiters {
            if waiter.occupied
                && waiter.state == CompletionWaiterState::Waiting
                && waiter.timeout_ns > 0
            {
                let elapsed = now_ns.saturating_sub(waiter.enqueue_ns);
                if elapsed >= waiter.timeout_ns {
                    waiter.state = CompletionWaiterState::TimedOut;
                    timed_out += 1;
                }
            }
        }
        timed_out
    }

    /// Cleans up completed/timed-out waiters from the queue.
    pub fn cleanup(&mut self) -> usize {
        let mut removed = 0;
        for waiter in &mut self.waiters {
            if waiter.occupied && waiter.state != CompletionWaiterState::Waiting {
                waiter.occupied = false;
                removed += 1;
            }
        }
        self.nr_waiters = self.nr_waiters.saturating_sub(removed);
        removed
    }

    /// Returns the state of a specific waiter by TID.
    pub fn waiter_state(&self, tid: u32) -> Option<CompletionWaiterState> {
        self.waiters
            .iter()
            .find(|w| w.occupied && w.tid == tid)
            .map(|w| w.state)
    }
}

// ======================================================================
// Completion registry
// ======================================================================

/// Manages a set of named completions.
pub struct CompletionRegistry {
    /// Completions.
    completions: [Completion; MAX_COMPLETIONS],
    /// Whether each slot is in use.
    occupied: [bool; MAX_COMPLETIONS],
    /// IDs for each completion.
    ids: [u32; MAX_COMPLETIONS],
    /// Number of registered completions.
    count: usize,
    /// Next ID.
    next_id: u32,
}

impl CompletionRegistry {
    /// Creates a new empty registry.
    pub const fn new() -> Self {
        Self {
            completions: [const { Completion::new() }; MAX_COMPLETIONS],
            occupied: [false; MAX_COMPLETIONS],
            ids: [0; MAX_COMPLETIONS],
            count: 0,
            next_id: 1,
        }
    }

    /// Returns the number of registered completions.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Creates a new completion and returns its ID.
    pub fn create(&mut self) -> Result<u32> {
        let slot = self
            .occupied
            .iter()
            .position(|&o| !o)
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.completions[slot] = Completion::new();
        self.ids[slot] = id;
        self.occupied[slot] = true;
        self.count += 1;
        Ok(id)
    }

    /// Destroys a completion by ID.
    pub fn destroy(&mut self, id: u32) -> Result<()> {
        let slot = self.find(id)?;
        self.occupied[slot] = false;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Signals a completion by ID.
    pub fn complete(&mut self, id: u32) -> Result<()> {
        let slot = self.find(id)?;
        self.completions[slot].complete();
        Ok(())
    }

    /// Signals all waiters on a completion.
    pub fn complete_all(&mut self, id: u32) -> Result<()> {
        let slot = self.find(id)?;
        self.completions[slot].complete_all();
        Ok(())
    }

    /// Waits on a completion by ID.
    pub fn wait(&mut self, id: u32, tid: u32, now_ns: u64) -> Result<()> {
        let slot = self.find(id)?;
        self.completions[slot].wait_for_completion(tid, now_ns)
    }

    /// Returns a reference to a completion by ID.
    pub fn get(&self, id: u32) -> Result<&Completion> {
        let slot = self.find(id)?;
        Ok(&self.completions[slot])
    }

    /// Finds a slot by ID.
    fn find(&self, id: u32) -> Result<usize> {
        for i in 0..MAX_COMPLETIONS {
            if self.occupied[i] && self.ids[i] == id {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }
}
