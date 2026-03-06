// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Wait-on-bit operations.
//!
//! Provides infrastructure for waiting until a specific bit in a
//! flags word is cleared (or set). Used by the page cache
//! (PG_locked), buffer heads, and other subsystems that use single
//! bits as synchronization primitives.
//!
//! # Flow
//!
//! ```text
//!   Thread A:                    Thread B:
//!   wait_on_bit(flags, BIT)      ...
//!     bit is set → enqueue       set_bit(flags, BIT)
//!     sleep                      finish work
//!                                clear_bit(flags, BIT)
//!     woken up ←──────────────── wake_up_bit(flags, BIT)
//!     check bit → clear → done
//! ```
//!
//! # Reference
//!
//! Linux `kernel/sched/wait_bit.c`, `include/linux/wait_bit.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum number of wait-bit queues (hash table size).
const WAIT_BIT_TABLE_SIZE: usize = 64;

/// Maximum waiters per bucket.
const MAX_WAITERS_PER_BUCKET: usize = 32;

/// Total maximum waiters across all buckets.
const _MAX_TOTAL_WAITERS: usize = WAIT_BIT_TABLE_SIZE * MAX_WAITERS_PER_BUCKET;

/// Wait action: sleep until bit is clear.
const _ACTION_SLEEP: u8 = 0;
/// Wait action: sleep in I/O wait state.
const _ACTION_IO: u8 = 1;
/// Wait action: sleep with timeout.
const _ACTION_TIMEOUT: u8 = 2;

// ======================================================================
// Wait bit key
// ======================================================================

/// Identifies which bit on which word we are waiting for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitBitKey {
    /// Identifier for the flags word (simulated pointer as u64).
    flags_id: u64,
    /// Bit number within the word.
    bit_nr: u8,
    /// Timeout in nanoseconds (0 = infinite).
    timeout_ns: u64,
}

impl WaitBitKey {
    /// Creates a new wait-bit key.
    pub const fn new(flags_id: u64, bit_nr: u8) -> Self {
        Self {
            flags_id,
            bit_nr,
            timeout_ns: 0,
        }
    }

    /// Creates a key with a timeout.
    pub const fn with_timeout(flags_id: u64, bit_nr: u8, timeout_ns: u64) -> Self {
        Self {
            flags_id,
            bit_nr,
            timeout_ns,
        }
    }

    /// Returns the flags identifier.
    pub fn flags_id(&self) -> u64 {
        self.flags_id
    }

    /// Returns the bit number.
    pub fn bit_nr(&self) -> u8 {
        self.bit_nr
    }

    /// Returns the timeout.
    pub fn timeout_ns(&self) -> u64 {
        self.timeout_ns
    }

    /// Computes the hash bucket index.
    pub fn bucket_index(&self) -> usize {
        let hash = self
            .flags_id
            .wrapping_mul(0x517cc1b727220a95)
            .wrapping_add(self.bit_nr as u64);
        (hash as usize) % WAIT_BIT_TABLE_SIZE
    }

    /// Returns true if the key matches another.
    pub fn matches(&self, other: &WaitBitKey) -> bool {
        self.flags_id == other.flags_id && self.bit_nr == other.bit_nr
    }
}

// ======================================================================
// Wait bit action
// ======================================================================

/// Describes the wait behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitBitAction {
    /// Sleep in TASK_UNINTERRUPTIBLE.
    Sleep,
    /// Sleep in TASK_UNINTERRUPTIBLE (I/O wait — counts as iowait).
    IoSleep,
    /// Sleep in TASK_INTERRUPTIBLE (can be interrupted by signal).
    Interruptible,
    /// Sleep with a timeout.
    Timeout,
}

// ======================================================================
// Waiter state
// ======================================================================

/// State of a single waiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaiterState {
    /// Waiter is sleeping.
    Sleeping,
    /// Waiter has been woken up.
    WokenUp,
    /// Waiter timed out.
    TimedOut,
    /// Waiter was interrupted by a signal.
    Interrupted,
}

// ======================================================================
// Wait bit entry
// ======================================================================

/// A single thread waiting on a bit.
#[derive(Debug, Clone, Copy)]
pub struct WaitBitEntry {
    /// The key identifying which bit is waited on.
    key: WaitBitKey,
    /// Thread ID of the waiter.
    tid: u32,
    /// Wait action type.
    action: WaitBitAction,
    /// Current state.
    state: WaiterState,
    /// Whether this slot is occupied.
    occupied: bool,
    /// Enqueue timestamp (ns).
    enqueue_ns: u64,
    /// Wake timestamp (ns, 0 if still sleeping).
    wake_ns: u64,
}

impl WaitBitEntry {
    /// Creates an empty waiter entry.
    pub const fn new() -> Self {
        Self {
            key: WaitBitKey::new(0, 0),
            tid: 0,
            action: WaitBitAction::Sleep,
            state: WaiterState::Sleeping,
            occupied: false,
            enqueue_ns: 0,
            wake_ns: 0,
        }
    }

    /// Returns the wait-bit key.
    pub fn key(&self) -> &WaitBitKey {
        &self.key
    }

    /// Returns the thread ID.
    pub fn tid(&self) -> u32 {
        self.tid
    }

    /// Returns the waiter state.
    pub fn state(&self) -> WaiterState {
        self.state
    }

    /// Returns whether this waiter is still sleeping.
    pub fn is_sleeping(&self) -> bool {
        self.state == WaiterState::Sleeping
    }

    /// Returns the wait duration (0 if still sleeping).
    pub fn wait_duration_ns(&self) -> u64 {
        if self.wake_ns > 0 {
            self.wake_ns.saturating_sub(self.enqueue_ns)
        } else {
            0
        }
    }
}

// ======================================================================
// Wait bit bucket
// ======================================================================

/// A hash bucket holding waiters for a range of keys.
pub struct WaitBitBucket {
    /// Waiter entries.
    entries: [WaitBitEntry; MAX_WAITERS_PER_BUCKET],
    /// Number of occupied entries.
    count: usize,
}

impl WaitBitBucket {
    /// Creates an empty bucket.
    pub const fn new() -> Self {
        Self {
            entries: [const { WaitBitEntry::new() }; MAX_WAITERS_PER_BUCKET],
            count: 0,
        }
    }

    /// Returns the number of waiters.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns whether the bucket is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Enqueues a waiter.
    pub fn enqueue(
        &mut self,
        key: WaitBitKey,
        tid: u32,
        action: WaitBitAction,
        now_ns: u64,
    ) -> Result<()> {
        let slot = self
            .entries
            .iter()
            .position(|e| !e.occupied)
            .ok_or(Error::OutOfMemory)?;
        self.entries[slot] = WaitBitEntry {
            key,
            tid,
            action,
            state: WaiterState::Sleeping,
            occupied: true,
            enqueue_ns: now_ns,
            wake_ns: 0,
        };
        self.count += 1;
        Ok(())
    }

    /// Wakes all waiters matching a key.
    pub fn wake(&mut self, key: &WaitBitKey, now_ns: u64) -> usize {
        let mut woken = 0;
        for entry in &mut self.entries {
            if entry.occupied && entry.state == WaiterState::Sleeping && entry.key.matches(key) {
                entry.state = WaiterState::WokenUp;
                entry.wake_ns = now_ns;
                woken += 1;
            }
        }
        woken
    }

    /// Wakes the first waiter matching a key (exclusive wake).
    pub fn wake_one(&mut self, key: &WaitBitKey, now_ns: u64) -> bool {
        for entry in &mut self.entries {
            if entry.occupied && entry.state == WaiterState::Sleeping && entry.key.matches(key) {
                entry.state = WaiterState::WokenUp;
                entry.wake_ns = now_ns;
                return true;
            }
        }
        false
    }

    /// Checks and removes woken or timed-out entries.
    pub fn cleanup(&mut self) -> usize {
        let mut removed = 0;
        for entry in &mut self.entries {
            if entry.occupied && entry.state != WaiterState::Sleeping {
                entry.occupied = false;
                removed += 1;
            }
        }
        self.count = self.count.saturating_sub(removed);
        removed
    }

    /// Times out entries that have exceeded their timeout.
    pub fn check_timeouts(&mut self, now_ns: u64) -> usize {
        let mut timed_out = 0;
        for entry in &mut self.entries {
            if entry.occupied && entry.state == WaiterState::Sleeping && entry.key.timeout_ns > 0 {
                let elapsed = now_ns.saturating_sub(entry.enqueue_ns);
                if elapsed >= entry.key.timeout_ns {
                    entry.state = WaiterState::TimedOut;
                    entry.wake_ns = now_ns;
                    timed_out += 1;
                }
            }
        }
        timed_out
    }
}

// ======================================================================
// Wait bit queue (hash table)
// ======================================================================

/// Global wait-on-bit hash table.
pub struct WaitBitQueue {
    /// Hash buckets.
    buckets: [WaitBitBucket; WAIT_BIT_TABLE_SIZE],
    /// Total number of active waiters.
    total_waiters: usize,
    /// Total wakeups performed.
    total_wakeups: u64,
    /// Total timeouts.
    total_timeouts: u64,
}

impl WaitBitQueue {
    /// Creates a new wait-bit queue.
    pub const fn new() -> Self {
        Self {
            buckets: [const { WaitBitBucket::new() }; WAIT_BIT_TABLE_SIZE],
            total_waiters: 0,
            total_wakeups: 0,
            total_timeouts: 0,
        }
    }

    /// Returns the total number of waiters.
    pub fn total_waiters(&self) -> usize {
        self.total_waiters
    }

    /// Returns the total wakeup count.
    pub fn total_wakeups(&self) -> u64 {
        self.total_wakeups
    }

    /// Returns the total timeout count.
    pub fn total_timeouts(&self) -> u64 {
        self.total_timeouts
    }

    /// Waits on a bit (enqueues a waiter).
    pub fn wait_on_bit(
        &mut self,
        key: WaitBitKey,
        tid: u32,
        action: WaitBitAction,
        now_ns: u64,
    ) -> Result<()> {
        let bucket = key.bucket_index();
        self.buckets[bucket].enqueue(key, tid, action, now_ns)?;
        self.total_waiters += 1;
        Ok(())
    }

    /// Waits on a bit with I/O accounting.
    pub fn wait_on_bit_io(
        &mut self,
        flags_id: u64,
        bit_nr: u8,
        tid: u32,
        now_ns: u64,
    ) -> Result<()> {
        let key = WaitBitKey::new(flags_id, bit_nr);
        self.wait_on_bit(key, tid, WaitBitAction::IoSleep, now_ns)
    }

    /// Wakes all waiters on a bit.
    pub fn wake_up_bit(&mut self, flags_id: u64, bit_nr: u8, now_ns: u64) -> usize {
        let key = WaitBitKey::new(flags_id, bit_nr);
        let bucket = key.bucket_index();
        let woken = self.buckets[bucket].wake(&key, now_ns);
        self.total_wakeups = self.total_wakeups.saturating_add(woken as u64);
        woken
    }

    /// Wakes one waiter on a bit (exclusive).
    pub fn wake_up_bit_one(&mut self, flags_id: u64, bit_nr: u8, now_ns: u64) -> bool {
        let key = WaitBitKey::new(flags_id, bit_nr);
        let bucket = key.bucket_index();
        let woken = self.buckets[bucket].wake_one(&key, now_ns);
        if woken {
            self.total_wakeups = self.total_wakeups.saturating_add(1);
        }
        woken
    }

    /// Checks timeouts across all buckets.
    pub fn check_timeouts(&mut self, now_ns: u64) -> usize {
        let mut total = 0;
        for bucket in &mut self.buckets {
            total += bucket.check_timeouts(now_ns);
        }
        self.total_timeouts = self.total_timeouts.saturating_add(total as u64);
        total
    }

    /// Cleans up completed entries and updates counts.
    pub fn cleanup(&mut self) {
        let mut removed = 0;
        for bucket in &mut self.buckets {
            removed += bucket.cleanup();
        }
        self.total_waiters = self.total_waiters.saturating_sub(removed);
    }
}
