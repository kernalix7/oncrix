// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! futex_waitv — wait on multiple futex addresses simultaneously.
//!
//! Extends the classic futex with the ability to block on multiple
//! futex words at once, waking when any of them changes. This is
//! essential for efficient cross-platform synchronisation (e.g.,
//! Windows WaitForMultipleObjects emulation in Wine/Proton).
//!
//! # Architecture
//!
//! ```text
//! FutexWaitvManager
//!  ├── waiters[MAX_WAITERS]
//!  │    ├── task_id
//!  │    ├── entries[MAX_ENTRIES_PER_WAIT]
//!  │    │    ├── uaddr, val, flags
//!  │    │    └── matched: bool
//!  │    └── state: WaitvState
//!  └── stats: WaitvStats
//! ```
//!
//! # Reference
//!
//! Linux `kernel/futex/waitv.c` — `sys_futex_waitv()`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum concurrent waitv operations.
const MAX_WAITERS: usize = 128;

/// Maximum futex entries per waitv call.
const MAX_ENTRIES_PER_WAIT: usize = 16;

// ══════════════════════════════════════════════════════════════
// FutexWaitvFlags
// ══════════════════════════════════════════════════════════════

/// Flags for a futex_waitv entry.
#[derive(Debug, Clone, Copy)]
pub struct FutexWaitvFlags {
    /// Use private (process-local) futex hash.
    pub is_private: bool,
    /// Futex size: false = 32-bit, true = 64-bit.
    pub is_64bit: bool,
    /// Use realtime clock for timeout.
    pub clock_realtime: bool,
}

impl FutexWaitvFlags {
    /// Default flags (private, 32-bit, monotonic).
    const fn default_flags() -> Self {
        Self {
            is_private: true,
            is_64bit: false,
            clock_realtime: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// WaitvEntry — a single futex in the wait set
// ══════════════════════════════════════════════════════════════

/// One entry in a futex_waitv wait set.
#[derive(Debug, Clone, Copy)]
pub struct WaitvEntry {
    /// User-space address of the futex word.
    pub uaddr: u64,
    /// Expected value at the address.
    pub val: u64,
    /// Entry-specific flags.
    pub flags: FutexWaitvFlags,
    /// Whether this entry matched (woke the waiter).
    pub matched: bool,
    /// Whether this entry is used.
    pub active: bool,
}

impl WaitvEntry {
    /// Create an inactive entry.
    const fn empty() -> Self {
        Self {
            uaddr: 0,
            val: 0,
            flags: FutexWaitvFlags::default_flags(),
            matched: false,
            active: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// WaitvState
// ══════════════════════════════════════════════════════════════

/// State of a waitv operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WaitvState {
    /// Slot is free.
    Free = 0,
    /// Setting up entries (not yet sleeping).
    Setup = 1,
    /// Blocked, waiting for any futex to be woken.
    Waiting = 2,
    /// Woken — at least one entry matched.
    Woken = 3,
    /// Timed out.
    TimedOut = 4,
}

// ══════════════════════════════════════════════════════════════
// WaitvWaiter
// ══════════════════════════════════════════════════════════════

/// A single waitv operation (one task waiting on multiple futexes).
#[derive(Clone, Copy)]
pub struct WaitvWaiter {
    /// Waiting task identifier.
    pub task_id: u64,
    /// Entries being waited on.
    pub entries: [WaitvEntry; MAX_ENTRIES_PER_WAIT],
    /// Number of active entries.
    pub nr_entries: u8,
    /// Timeout (absolute, monotonic ns; 0 = infinite).
    pub timeout_ns: u64,
    /// Current state.
    pub state: WaitvState,
    /// Index of the entry that woke us (-1 = none).
    pub woken_index: i32,
}

impl WaitvWaiter {
    /// Create a free waiter slot.
    const fn empty() -> Self {
        Self {
            task_id: 0,
            entries: [const { WaitvEntry::empty() }; MAX_ENTRIES_PER_WAIT],
            nr_entries: 0,
            timeout_ns: 0,
            state: WaitvState::Free,
            woken_index: -1,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// WaitvStats
// ══════════════════════════════════════════════════════════════

/// Statistics for the futex_waitv subsystem.
#[derive(Debug, Clone, Copy)]
pub struct WaitvStats {
    /// Total waitv calls.
    pub total_waits: u64,
    /// Total wakeups.
    pub total_wakes: u64,
    /// Total timeouts.
    pub total_timeouts: u64,
    /// Total entries across all waits.
    pub total_entries: u64,
}

impl WaitvStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            total_waits: 0,
            total_wakes: 0,
            total_timeouts: 0,
            total_entries: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// FutexWaitvManager
// ══════════════════════════════════════════════════════════════

/// Manages futex_waitv operations.
pub struct FutexWaitvManager {
    /// Waiter table.
    waiters: [WaitvWaiter; MAX_WAITERS],
    /// Statistics.
    stats: WaitvStats,
}

impl FutexWaitvManager {
    /// Create a new futex_waitv manager.
    pub const fn new() -> Self {
        Self {
            waiters: [const { WaitvWaiter::empty() }; MAX_WAITERS],
            stats: WaitvStats::new(),
        }
    }

    /// Begin a waitv operation.
    ///
    /// Returns the waiter slot index.
    pub fn setup_wait(
        &mut self,
        task_id: u64,
        entries: &[(u64, u64)], // (uaddr, val) pairs
        timeout_ns: u64,
    ) -> Result<usize> {
        if entries.is_empty() || entries.len() > MAX_ENTRIES_PER_WAIT {
            return Err(Error::InvalidArgument);
        }
        let slot = self
            .waiters
            .iter()
            .position(|w| matches!(w.state, WaitvState::Free))
            .ok_or(Error::OutOfMemory)?;
        let waiter = &mut self.waiters[slot];
        waiter.task_id = task_id;
        waiter.timeout_ns = timeout_ns;
        waiter.state = WaitvState::Setup;
        waiter.nr_entries = entries.len() as u8;
        waiter.woken_index = -1;
        for (i, (uaddr, val)) in entries.iter().enumerate() {
            waiter.entries[i] = WaitvEntry {
                uaddr: *uaddr,
                val: *val,
                flags: FutexWaitvFlags::default_flags(),
                matched: false,
                active: true,
            };
        }
        self.stats.total_waits += 1;
        self.stats.total_entries += entries.len() as u64;
        Ok(slot)
    }

    /// Transition a waiter to the Waiting (blocked) state.
    pub fn start_wait(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_WAITERS {
            return Err(Error::InvalidArgument);
        }
        if !matches!(self.waiters[slot].state, WaitvState::Setup) {
            return Err(Error::InvalidArgument);
        }
        self.waiters[slot].state = WaitvState::Waiting;
        Ok(())
    }

    /// Wake a waiter because a futex at `uaddr` was signalled.
    ///
    /// Returns `true` if a waiter was woken.
    pub fn wake_by_addr(&mut self, uaddr: u64) -> bool {
        for waiter in &mut self.waiters {
            if !matches!(waiter.state, WaitvState::Waiting) {
                continue;
            }
            for (i, entry) in waiter.entries.iter_mut().enumerate() {
                if entry.active && entry.uaddr == uaddr {
                    entry.matched = true;
                    waiter.state = WaitvState::Woken;
                    waiter.woken_index = i as i32;
                    self.stats.total_wakes += 1;
                    return true;
                }
            }
        }
        false
    }

    /// Mark a waiter as timed out.
    pub fn timeout(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_WAITERS {
            return Err(Error::InvalidArgument);
        }
        if !matches!(self.waiters[slot].state, WaitvState::Waiting) {
            return Err(Error::InvalidArgument);
        }
        self.waiters[slot].state = WaitvState::TimedOut;
        self.stats.total_timeouts += 1;
        Ok(())
    }

    /// Clean up a completed waiter and return which entry matched.
    pub fn finish_wait(&mut self, slot: usize) -> Result<i32> {
        if slot >= MAX_WAITERS {
            return Err(Error::InvalidArgument);
        }
        let idx = self.waiters[slot].woken_index;
        self.waiters[slot] = WaitvWaiter::empty();
        Ok(idx)
    }

    /// Return statistics.
    pub fn stats(&self) -> WaitvStats {
        self.stats
    }
}
