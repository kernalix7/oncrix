// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Round-robin scheduler.
//!
//! A simple fixed-timeslice scheduler that cycles through ready threads
//! in a circular queue. This serves as the initial scheduler; it will
//! be replaced with a multi-level feedback queue (MLFQ) in the future.

use crate::pid::Tid;
use crate::thread::{Thread, ThreadState};
use oncrix_lib::{Error, Result};

/// Maximum number of threads the scheduler can manage.
const MAX_THREADS: usize = 256;

/// Round-robin scheduler.
///
/// Maintains a fixed-size array of thread slots and a cursor pointing
/// to the next candidate. Scheduling is O(N) worst-case per pick,
/// where N = MAX_THREADS.
pub struct RoundRobinScheduler {
    /// Thread slots (None = empty).
    threads: [Option<Thread>; MAX_THREADS],
    /// Number of threads currently registered.
    count: usize,
    /// Index of the currently running thread (None if idle).
    current: Option<usize>,
    /// Cursor for round-robin scanning.
    cursor: usize,
}

impl Default for RoundRobinScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl RoundRobinScheduler {
    /// Create a new empty scheduler.
    pub const fn new() -> Self {
        // SAFETY: Option<Thread> is None when zero-initialized for
        // types without non-zero requirements, but we use explicit
        // None initialization via const array.
        const NONE: Option<Thread> = None;
        Self {
            threads: [NONE; MAX_THREADS],
            count: 0,
            current: None,
            cursor: 0,
        }
    }

    /// Add a thread to the scheduler.
    ///
    /// The thread must be in the `Ready` state.
    pub fn add(&mut self, thread: Thread) -> Result<()> {
        if thread.state() != ThreadState::Ready {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_THREADS {
            return Err(Error::OutOfMemory);
        }

        // Find first empty slot.
        for slot in self.threads.iter_mut() {
            if slot.is_none() {
                *slot = Some(thread);
                self.count += 1;
                return Ok(());
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Remove a thread by TID.
    ///
    /// Returns the removed thread, or `Err` if not found.
    pub fn remove(&mut self, tid: Tid) -> Result<Thread> {
        for (i, slot) in self.threads.iter_mut().enumerate() {
            if let Some(t) = slot.as_ref() {
                if t.tid() == tid {
                    let thread = slot.take().ok_or(Error::NotFound)?;
                    self.count -= 1;
                    // If we removed the current thread, clear it.
                    if self.current == Some(i) {
                        self.current = None;
                    }
                    return Ok(thread);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Pick the next ready thread to run (round-robin).
    ///
    /// If a thread is currently running, it is moved back to `Ready`.
    /// The next `Ready` thread in circular order is moved to `Running`.
    ///
    /// Returns the TID of the newly scheduled thread, or `None` if
    /// no threads are ready.
    pub fn schedule(&mut self) -> Option<Tid> {
        // Move current thread back to Ready.
        if let Some(idx) = self.current {
            if let Some(ref mut t) = self.threads[idx] {
                if t.state() == ThreadState::Running {
                    t.set_state(ThreadState::Ready);
                }
            }
            self.current = None;
        }

        // Scan for next Ready thread starting from cursor.
        for _ in 0..MAX_THREADS {
            let idx = self.cursor % MAX_THREADS;
            self.cursor = (self.cursor + 1) % MAX_THREADS;

            if let Some(ref mut t) = self.threads[idx] {
                if t.state() == ThreadState::Ready {
                    t.set_state(ThreadState::Running);
                    self.current = Some(idx);
                    return Some(t.tid());
                }
            }
        }

        None
    }

    /// Get the currently running thread's TID.
    pub fn current_tid(&self) -> Option<Tid> {
        self.current
            .and_then(|idx| self.threads[idx].as_ref())
            .map(|t| t.tid())
    }

    /// Get a reference to a thread by TID.
    pub fn get(&self, tid: Tid) -> Option<&Thread> {
        self.threads
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|t| t.tid() == tid)
    }

    /// Get a mutable reference to a thread by TID.
    pub fn get_mut(&mut self, tid: Tid) -> Option<&mut Thread> {
        self.threads
            .iter_mut()
            .filter_map(|s| s.as_mut())
            .find(|t| t.tid() == tid)
    }

    /// Block the currently running thread (e.g., waiting for IPC).
    ///
    /// The blocked thread will not be picked by `schedule()` until
    /// it is explicitly unblocked.
    pub fn block_current(&mut self) -> Result<()> {
        let idx = self.current.ok_or(Error::NotFound)?;
        if let Some(ref mut t) = self.threads[idx] {
            t.set_state(ThreadState::Blocked);
        }
        self.current = None;
        Ok(())
    }

    /// Unblock a thread by TID, moving it to `Ready`.
    pub fn unblock(&mut self, tid: Tid) -> Result<()> {
        let thread = self.get_mut(tid).ok_or(Error::NotFound)?;
        if thread.state() != ThreadState::Blocked {
            return Err(Error::InvalidArgument);
        }
        thread.set_state(ThreadState::Ready);
        Ok(())
    }

    /// Return the total number of registered threads.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Return the number of ready threads.
    pub fn ready_count(&self) -> usize {
        self.threads
            .iter()
            .filter_map(|s| s.as_ref())
            .filter(|t| t.state() == ThreadState::Ready)
            .count()
    }
}
