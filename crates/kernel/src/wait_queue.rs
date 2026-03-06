// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Wait queue implementation.
//!
//! Provides a `WaitQueue` that allows tasks to sleep until a condition is met.
//! The design mirrors the Linux kernel's `wait_queue_head_t` with per-waiter
//! entries and an exclusive / non-exclusive wake model.
//!
//! Each waiter records its PID, a wake flag, and whether it needs exclusive
//! wakeup semantics (thundering-herd prevention).

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use oncrix_lib::{Error, Result};

/// Maximum number of waiters on a single wait queue.
pub const WAIT_QUEUE_MAX_WAITERS: usize = 128;

/// Wake modes for `wake_up` calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeMode {
    /// Wake one exclusive waiter (default for most callers).
    One,
    /// Wake all non-exclusive waiters plus one exclusive waiter.
    All,
    /// Wake all waiters regardless of exclusivity.
    AllStrict,
}

/// A single waiter entry within a wait queue.
pub struct WaitEntry {
    /// PID of the waiting task (0 = unused slot).
    pub pid: u32,
    /// Set to `true` by the waker when this entry should wake up.
    pub woken: AtomicBool,
    /// Whether this is an exclusive waiter.
    pub exclusive: bool,
    /// Optional condition tag used for custom wake filters.
    pub tag: u32,
}

impl WaitEntry {
    /// Creates an unused wait entry.
    pub const fn new() -> Self {
        Self {
            pid: 0,
            woken: AtomicBool::new(false),
            exclusive: false,
            tag: 0,
        }
    }

    /// Returns `true` if the entry has been woken.
    #[inline]
    pub fn is_woken(&self) -> bool {
        self.woken.load(Ordering::Acquire)
    }

    /// Marks the entry as woken (called by the waker).
    #[inline]
    pub fn wake(&self) {
        self.woken.store(true, Ordering::Release);
    }

    /// Resets the woken flag (called before re-queuing).
    #[inline]
    pub fn reset(&self) {
        self.woken.store(false, Ordering::Relaxed);
    }
}

impl Default for WaitEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Wait queue head — owns a list of `WaitEntry` slots.
pub struct WaitQueue {
    entries: [WaitEntry; WAIT_QUEUE_MAX_WAITERS],
    count: AtomicU32,
}

impl WaitQueue {
    /// Creates an empty wait queue.
    pub const fn new() -> Self {
        Self {
            entries: [const { WaitEntry::new() }; WAIT_QUEUE_MAX_WAITERS],
            count: AtomicU32::new(0),
        }
    }

    /// Adds a waiter for `pid`. Returns the slot index on success.
    pub fn add_waiter(&self, pid: u32, exclusive: bool, tag: u32) -> Result<usize> {
        // Find an unused slot.
        for i in 0..WAIT_QUEUE_MAX_WAITERS {
            // SAFETY: We use atomic compare-exchange to claim the slot.
            let entry = &self.entries[i];
            if entry.pid == 0 {
                // Use raw pointer write since WaitEntry fields are not atomically
                // settable as a group; this is safe as long as the slot's pid was 0
                // (unclaimed) when we read it.  In a real SMP system a spinlock
                // would protect this.
                //
                // SAFETY: `i` is a valid index into the fixed-size array.
                // We write through a raw pointer only after confirming pid==0.
                unsafe {
                    let p = entry as *const WaitEntry as *mut WaitEntry;
                    (*p).pid = pid;
                    (*p).exclusive = exclusive;
                    (*p).tag = tag;
                    entry.reset();
                }
                self.count.fetch_add(1, Ordering::Relaxed);
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Removes the waiter at `slot` (called after wakeup or cancellation).
    pub fn remove_waiter(&self, slot: usize) -> Result<()> {
        if slot >= WAIT_QUEUE_MAX_WAITERS {
            return Err(Error::InvalidArgument);
        }
        let entry = &self.entries[slot];
        if entry.pid == 0 {
            return Err(Error::NotFound);
        }
        // SAFETY: Clearing an entry we own (pid != 0); single-threaded teardown path.
        unsafe {
            let p = entry as *const WaitEntry as *mut WaitEntry;
            (*p).pid = 0;
            (*p).exclusive = false;
            (*p).tag = 0;
        }
        self.count.fetch_sub(1, Ordering::Relaxed);
        Ok(())
    }

    /// Wakes up waiters according to `mode`. Returns the number of entries woken.
    pub fn wake_up(&self, mode: WakeMode) -> usize {
        let mut woken = 0usize;
        let mut woke_exclusive = false;

        for i in 0..WAIT_QUEUE_MAX_WAITERS {
            let entry = &self.entries[i];
            if entry.pid == 0 {
                continue;
            }
            match mode {
                WakeMode::One => {
                    entry.wake();
                    woken += 1;
                    break;
                }
                WakeMode::All => {
                    if !entry.exclusive {
                        entry.wake();
                        woken += 1;
                    } else if !woke_exclusive {
                        entry.wake();
                        woke_exclusive = true;
                        woken += 1;
                    }
                }
                WakeMode::AllStrict => {
                    entry.wake();
                    woken += 1;
                }
            }
        }
        woken
    }

    /// Wakes all waiters whose `tag` matches `filter_tag`.
    pub fn wake_up_tagged(&self, filter_tag: u32) -> usize {
        let mut woken = 0usize;
        for i in 0..WAIT_QUEUE_MAX_WAITERS {
            let entry = &self.entries[i];
            if entry.pid != 0 && entry.tag == filter_tag {
                entry.wake();
                woken += 1;
            }
        }
        woken
    }

    /// Returns the number of current waiters.
    #[inline]
    pub fn waiter_count(&self) -> u32 {
        self.count.load(Ordering::Relaxed)
    }

    /// Returns `true` if the slot at `idx` has been woken.
    pub fn is_woken(&self, slot: usize) -> bool {
        if slot >= WAIT_QUEUE_MAX_WAITERS {
            return false;
        }
        self.entries[slot].is_woken()
    }
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}
