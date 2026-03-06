// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Futex (Fast User-space muTEX) implementation.
//!
//! Futexes are the kernel-side building block for user-space
//! synchronization primitives (mutexes, condition variables,
//! semaphores, barriers). The kernel only intervenes when
//! contention occurs — the fast path is entirely in user space.
//!
//! Operations:
//! - `FUTEX_WAIT`: sleep if `*uaddr == val`
//! - `FUTEX_WAKE`: wake up to `val` waiters on `uaddr`
//!
//! Reference: Linux `kernel/futex/`, futex(2) man page.

use oncrix_lib::{Error, Result};
use oncrix_process::pid::Pid;

/// Futex operation codes (matches Linux values).
pub mod ops {
    /// Sleep if `*uaddr == val`.
    pub const FUTEX_WAIT: u32 = 0;
    /// Wake up to `val` waiters.
    pub const FUTEX_WAKE: u32 = 1;
    /// Private futex flag (no cross-process sharing).
    pub const FUTEX_PRIVATE_FLAG: u32 = 128;
    /// Wait with private flag.
    pub const FUTEX_WAIT_PRIVATE: u32 = FUTEX_WAIT | FUTEX_PRIVATE_FLAG;
    /// Wake with private flag.
    pub const FUTEX_WAKE_PRIVATE: u32 = FUTEX_WAKE | FUTEX_PRIVATE_FLAG;
}

/// Maximum number of concurrent futex waiters system-wide.
const MAX_WAITERS: usize = 512;

/// Number of hash buckets for the futex table.
const HASH_BUCKETS: usize = 64;

/// A single futex waiter.
#[derive(Debug, Clone, Copy)]
struct FutexWaiter {
    /// User-space address being waited on.
    uaddr: u64,
    /// Process that is waiting.
    pid: Pid,
    /// Thread ID within the process (for targeted wakeup).
    tid: u64,
    /// Whether this waiter is active (not yet woken).
    active: bool,
}

/// Global futex wait table.
///
/// Uses a hash table of wait queues. Each bucket holds waiters
/// that hash to the same slot. Lookup is O(bucket_size).
pub struct FutexTable {
    /// Waiter pool (flat array, hash-indexed).
    waiters: [Option<FutexWaiter>; MAX_WAITERS],
    /// Number of active waiters.
    count: usize,
}

impl Default for FutexTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FutexTable {
    /// Create an empty futex table.
    pub const fn new() -> Self {
        const NONE: Option<FutexWaiter> = None;
        Self {
            waiters: [NONE; MAX_WAITERS],
            count: 0,
        }
    }

    /// FUTEX_WAIT: add a waiter if `*uaddr == expected_val`.
    ///
    /// The caller must read `*uaddr` and compare it to `expected_val`
    /// atomically (or under appropriate locking) before calling this.
    /// If the value has changed, returns `WouldBlock` (EAGAIN).
    ///
    /// `current_val` is the value read from `*uaddr` by the caller.
    ///
    /// On success, the calling thread should be put to sleep.
    /// It will be woken by a subsequent `futex_wake` on the same address.
    pub fn futex_wait(
        &mut self,
        uaddr: u64,
        expected_val: u32,
        current_val: u32,
        pid: Pid,
        tid: u64,
    ) -> Result<()> {
        // Check if the value has changed since the caller read it.
        if current_val != expected_val {
            return Err(Error::WouldBlock);
        }

        if self.count >= MAX_WAITERS {
            return Err(Error::OutOfMemory);
        }

        // Find a free slot (prefer hash-based placement).
        let start = hash_uaddr(uaddr);
        for i in 0..MAX_WAITERS {
            let idx = (start + i) % MAX_WAITERS;
            if self.waiters[idx].is_none() {
                self.waiters[idx] = Some(FutexWaiter {
                    uaddr,
                    pid,
                    tid,
                    active: true,
                });
                self.count += 1;
                return Ok(());
            }
        }

        Err(Error::OutOfMemory)
    }

    /// FUTEX_WAKE: wake up to `max_wake` waiters on `uaddr`.
    ///
    /// Returns the number of waiters actually woken. The caller
    /// is responsible for actually unblocking the threads (e.g.,
    /// moving them from blocked to runnable in the scheduler).
    pub fn futex_wake(&mut self, uaddr: u64, max_wake: u32) -> WakeResult {
        let mut woken = 0u32;
        let mut woken_pids = [WokenThread::EMPTY; 32];

        let start = hash_uaddr(uaddr);
        for i in 0..MAX_WAITERS {
            if woken >= max_wake || woken >= 32 {
                break;
            }

            let idx = (start + i) % MAX_WAITERS;
            if let Some(waiter) = &self.waiters[idx] {
                if waiter.uaddr == uaddr && waiter.active {
                    woken_pids[woken as usize] = WokenThread {
                        pid: waiter.pid,
                        tid: waiter.tid,
                    };
                    self.waiters[idx] = None;
                    self.count = self.count.saturating_sub(1);
                    woken += 1;
                }
            }
        }

        // If hash-based scan didn't find enough, do a full scan.
        if woken < max_wake {
            for idx in 0..MAX_WAITERS {
                if woken >= max_wake || woken >= 32 {
                    break;
                }
                if let Some(waiter) = &self.waiters[idx] {
                    if waiter.uaddr == uaddr && waiter.active {
                        woken_pids[woken as usize] = WokenThread {
                            pid: waiter.pid,
                            tid: waiter.tid,
                        };
                        self.waiters[idx] = None;
                        self.count = self.count.saturating_sub(1);
                        woken += 1;
                    }
                }
            }
        }

        WakeResult {
            woken,
            threads: woken_pids,
        }
    }

    /// Remove all waiters for a given process (e.g., on process exit).
    pub fn remove_process(&mut self, pid: Pid) {
        for slot in self.waiters.iter_mut() {
            if let Some(waiter) = slot {
                if waiter.pid == pid {
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                }
            }
        }
    }

    /// Return the number of active waiters.
    pub fn waiter_count(&self) -> usize {
        self.count
    }
}

/// A thread that was woken by futex_wake.
#[derive(Debug, Clone, Copy)]
pub struct WokenThread {
    /// Process ID.
    pub pid: Pid,
    /// Thread ID.
    pub tid: u64,
}

impl WokenThread {
    const EMPTY: Self = Self {
        pid: Pid::KERNEL,
        tid: 0,
    };
}

/// Result of a futex_wake operation.
#[derive(Debug)]
pub struct WakeResult {
    /// Number of threads woken.
    pub woken: u32,
    /// The woken threads (up to 32).
    pub threads: [WokenThread; 32],
}

/// Hash a user-space address to a bucket index.
fn hash_uaddr(uaddr: u64) -> usize {
    // Simple multiplicative hash (golden ratio).
    let h = uaddr.wrapping_mul(0x9E3779B97F4A7C15);
    (h >> 48) as usize % HASH_BUCKETS
}

impl core::fmt::Debug for FutexTable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FutexTable")
            .field("active_waiters", &self.count)
            .field("capacity", &MAX_WAITERS)
            .finish()
    }
}
