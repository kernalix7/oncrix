// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Futex requeue operations: `FUTEX_REQUEUE` and `FUTEX_CMP_REQUEUE`.
//!
//! Requeue operations allow waking some waiters on one futex and atomically
//! moving the remaining waiters to a second futex address.  This is the
//! primary mechanism used by `pthread_cond_broadcast` in glibc to avoid
//! the "thundering herd" problem when broadcasting on a condition variable.
//!
//! # Operations
//!
//! | Operation             | Function                  | Description                              |
//! |-----------------------|---------------------------|------------------------------------------|
//! | `FUTEX_REQUEUE`       | [`do_futex_requeue`]      | Wake N, requeue rest to `uaddr2`         |
//! | `FUTEX_CMP_REQUEUE`   | [`do_futex_cmp_requeue`]  | Same, but compare `*uaddr1 == cmpval` first |
//!
//! # Atomic guarantee
//!
//! The comparison in `FUTEX_CMP_REQUEUE` and the requeue must be atomic with
//! respect to concurrent `futex(FUTEX_WAKE)` calls on `uaddr1`.  In a real
//! kernel this is achieved by holding the hash bucket lock across both the
//! comparison and the queue manipulation.  In this stub the operations are
//! logically atomic.
//!
//! # References
//!
//! - Linux: `kernel/futex/requeue.c` — `futex_requeue()`
//! - `include/uapi/linux/futex.h` — `FUTEX_REQUEUE`, `FUTEX_CMP_REQUEUE`
//! - Ulrich Drepper, "Futexes Are Tricky" (2011)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Futex flags (subset relevant to requeue)
// ---------------------------------------------------------------------------

/// Futex lives in shared memory (process-shared semantics).
pub const FUTEX_SHARED_FLAG: u32 = 1 << 3;

/// Enable NUMA-aware hash bucket selection.
pub const FUTEX_NUMA_FLAG: u32 = 1 << 4;

/// Mask to extract the size field from flags.
pub const FUTEX_SIZE_MASK: u32 = 0x03;

/// Futex value is a `u32` (the classic Linux futex size).
pub const FUTEX_SIZE_U32: u32 = 0x02;

/// All recognised futex flags.
const FUTEX_FLAGS_KNOWN: u32 = FUTEX_SIZE_MASK | FUTEX_SHARED_FLAG | FUTEX_NUMA_FLAG;

// ---------------------------------------------------------------------------
// Waiter table
// ---------------------------------------------------------------------------

/// Maximum number of concurrent waiters.
pub const MAX_WAITERS: usize = 256;

/// A record of one thread waiting on a futex address.
#[derive(Debug, Clone, Copy)]
pub struct Waiter {
    /// User-space address of the futex word being waited on.
    pub uaddr: u64,
    /// Flags with which the wait was registered.
    pub flags: u32,
    /// Synthetic thread ID.
    pub tid: u32,
    /// Whether this waiter has been woken.
    pub woken: bool,
}

/// A flat table of futex waiters.
pub struct WaiterTable {
    waiters: [Option<Waiter>; MAX_WAITERS],
    count: usize,
}

impl WaiterTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            waiters: [const { None }; MAX_WAITERS],
            count: 0,
        }
    }

    /// Insert a waiter.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfMemory`] — table full.
    pub fn insert(&mut self, w: Waiter) -> Result<()> {
        for slot in self.waiters.iter_mut() {
            if slot.is_none() {
                *slot = Some(w);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Count waiters on `uaddr`.
    pub fn count_on(&self, uaddr: u64) -> u32 {
        self.waiters
            .iter()
            .filter_map(|s| s.as_ref())
            .filter(|w| w.uaddr == uaddr && !w.woken)
            .count() as u32
    }

    /// Wake up to `nr_wake` waiters on `uaddr`.
    ///
    /// Returns the number of waiters woken.
    pub fn wake(&mut self, uaddr: u64, nr_wake: u32) -> u32 {
        let mut woken = 0u32;
        for slot in self.waiters.iter_mut() {
            if woken >= nr_wake {
                break;
            }
            if let Some(w) = slot {
                if w.uaddr == uaddr && !w.woken {
                    w.woken = true;
                    woken += 1;
                }
            }
        }
        woken
    }

    /// Move up to `nr_requeue` non-woken waiters from `from_uaddr` to `to_uaddr`.
    ///
    /// Returns the number of waiters requeued.
    pub fn requeue(&mut self, from_uaddr: u64, to_uaddr: u64, nr_requeue: u32) -> u32 {
        let mut requeued = 0u32;
        for slot in self.waiters.iter_mut() {
            if requeued >= nr_requeue {
                break;
            }
            if let Some(w) = slot {
                if w.uaddr == from_uaddr && !w.woken {
                    w.uaddr = to_uaddr;
                    requeued += 1;
                }
            }
        }
        requeued
    }

    /// Check whether waiter `tid` on `uaddr` has been woken.
    pub fn is_woken(&self, tid: u32, uaddr: u64) -> bool {
        self.waiters
            .iter()
            .filter_map(|s| s.as_ref())
            .any(|w| w.tid == tid && w.uaddr == uaddr && w.woken)
    }

    /// Return the total number of active (not removed) waiter slots.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Remove a waiter by TID and original uaddr.
    pub fn remove(&mut self, tid: u32, uaddr: u64) {
        for slot in self.waiters.iter_mut() {
            if slot
                .as_ref()
                .is_some_and(|w| w.tid == tid && w.uaddr == uaddr)
            {
                *slot = None;
                self.count = self.count.saturating_sub(1);
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate futex flags: no unknown bits.
fn validate_flags(flags: u32) -> Result<()> {
    if flags & !FUTEX_FLAGS_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate that `uaddr` is non-null.
fn validate_addr(uaddr: u64) -> Result<()> {
    if uaddr == 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate that `uaddr1` and `uaddr2` are distinct.
///
/// The kernel (`futex_requeue`) explicitly rejects identical addresses
/// because requeuing to the same address is a no-op and likely a bug.
fn validate_distinct_addrs(uaddr1: u64, uaddr2: u64) -> Result<()> {
    if uaddr1 == uaddr2 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// RequeueResult — outcome of a requeue operation
// ---------------------------------------------------------------------------

/// Result of a futex requeue operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequeueResult {
    /// Number of waiters woken from `uaddr1`.
    pub woken: u32,
    /// Number of waiters moved from `uaddr1` to `uaddr2`.
    pub requeued: u32,
}

// ---------------------------------------------------------------------------
// do_futex_requeue
// ---------------------------------------------------------------------------

/// Handler for `futex(FUTEX_REQUEUE)`.
///
/// Wakes up to `nr_wake` threads waiting on `uaddr1`, then requeues up to
/// `nr_requeue` of the remaining waiters to `uaddr2`.  No value comparison
/// is performed on `*uaddr1`.
///
/// # Arguments
///
/// * `table`      — Global futex waiter table.
/// * `uaddr1`     — Source futex address.
/// * `uaddr2`     — Destination futex address.
/// * `nr_wake`    — Maximum number of waiters to wake.
/// * `nr_requeue` — Maximum number of waiters to move to `uaddr2`.
/// * `flags`      — Futex flags (size + shared/private + NUMA).
///
/// # Returns
///
/// A [`RequeueResult`] with the counts of woken and requeued waiters.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — Null or identical addresses, or bad flags.
pub fn do_futex_requeue(
    table: &mut WaiterTable,
    uaddr1: u64,
    uaddr2: u64,
    nr_wake: u32,
    nr_requeue: u32,
    flags: u32,
) -> Result<RequeueResult> {
    validate_flags(flags)?;
    validate_addr(uaddr1)?;
    validate_addr(uaddr2)?;
    validate_distinct_addrs(uaddr1, uaddr2)?;

    let woken = table.wake(uaddr1, nr_wake);
    let requeued = table.requeue(uaddr1, uaddr2, nr_requeue);

    Ok(RequeueResult { woken, requeued })
}

// ---------------------------------------------------------------------------
// do_futex_cmp_requeue
// ---------------------------------------------------------------------------

/// Handler for `futex(FUTEX_CMP_REQUEUE)`.
///
/// Same as [`do_futex_requeue`] but first atomically verifies that the
/// value at `uaddr1` equals `cmpval`.  If the comparison fails, the
/// operation is aborted and [`Error::WouldBlock`] is returned.
///
/// This is the core primitive used by condition-variable broadcast in
/// `glibc`.
///
/// # Arguments
///
/// * `table`      — Global futex waiter table.
/// * `uaddr1`     — Source futex address.
/// * `uaddr2`     — Destination futex address.
/// * `nr_wake`    — Maximum number of waiters to wake.
/// * `nr_requeue` — Maximum number of waiters to move to `uaddr2`.
/// * `cmpval`     — Expected value of `*uaddr1`.
/// * `flags`      — Futex flags (size + shared/private + NUMA).
/// * `current_val` — Current value at `*uaddr1` (caller read from user space).
///
/// # Returns
///
/// A [`RequeueResult`] with the counts of woken and requeued waiters.
///
/// # Errors
///
/// - [`Error::WouldBlock`]      — `*uaddr1 != cmpval`.
/// - [`Error::InvalidArgument`] — Null or identical addresses, or bad flags.
pub fn do_futex_cmp_requeue(
    table: &mut WaiterTable,
    uaddr1: u64,
    uaddr2: u64,
    nr_wake: u32,
    nr_requeue: u32,
    cmpval: u32,
    flags: u32,
    current_val: u32,
) -> Result<RequeueResult> {
    validate_flags(flags)?;
    validate_addr(uaddr1)?;
    validate_addr(uaddr2)?;
    validate_distinct_addrs(uaddr1, uaddr2)?;

    // Atomic comparison: abort if value changed.
    if current_val != cmpval {
        return Err(Error::WouldBlock);
    }

    let woken = table.wake(uaddr1, nr_wake);
    let requeued = table.requeue(uaddr1, uaddr2, nr_requeue);

    Ok(RequeueResult { woken, requeued })
}

// ---------------------------------------------------------------------------
// do_futex_cmp_requeue_pi (PI-futex variant)
// ---------------------------------------------------------------------------

/// Handler for `futex(FUTEX_CMP_REQUEUE_PI)`.
///
/// Priority-inheritance variant of `FUTEX_CMP_REQUEUE`.  Exactly one
/// waiter is woken from `uaddr1` (the highest-priority waiter), and the
/// rest are requeued to the PI-futex `uaddr2`.  This is used when
/// broadcasting on a PI-mutex-backed condition variable.
///
/// In this stub, priority inheritance is not tracked; the implementation
/// delegates to the same wake/requeue logic.
///
/// # Arguments
///
/// * `table`      — Global futex waiter table.
/// * `uaddr1`     — Source non-PI futex (the condition variable's internal lock).
/// * `uaddr2`     — Destination PI futex (the associated mutex).
/// * `nr_requeue` — Maximum number of waiters to requeue to `uaddr2`.
/// * `cmpval`     — Expected value of `*uaddr1`.
/// * `flags`      — Futex flags.
/// * `current_val` — Current value at `*uaddr1`.
///
/// # Errors
///
/// - [`Error::WouldBlock`]      — `*uaddr1 != cmpval`.
/// - [`Error::InvalidArgument`] — Bad arguments.
pub fn do_futex_cmp_requeue_pi(
    table: &mut WaiterTable,
    uaddr1: u64,
    uaddr2: u64,
    nr_requeue: u32,
    cmpval: u32,
    flags: u32,
    current_val: u32,
) -> Result<RequeueResult> {
    validate_flags(flags)?;
    validate_addr(uaddr1)?;
    validate_addr(uaddr2)?;
    validate_distinct_addrs(uaddr1, uaddr2)?;

    if current_val != cmpval {
        return Err(Error::WouldBlock);
    }

    // PI requeue: wake exactly 1, requeue the rest.
    let woken = table.wake(uaddr1, 1);
    let requeued = table.requeue(uaddr1, uaddr2, nr_requeue);

    Ok(RequeueResult { woken, requeued })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn add_waiters(table: &mut WaiterTable, uaddr: u64, count: u32) {
        for i in 0..count {
            table
                .insert(Waiter {
                    uaddr,
                    flags: FUTEX_SIZE_U32,
                    tid: i + 1,
                    woken: false,
                })
                .unwrap();
        }
    }

    // --- do_futex_requeue ---

    #[test]
    fn requeue_wakes_and_moves() {
        let mut t = WaiterTable::new();
        add_waiters(&mut t, 0x1000, 5);

        let res = do_futex_requeue(&mut t, 0x1000, 0x2000, 2, 3, FUTEX_SIZE_U32).unwrap();
        assert_eq!(res.woken, 2);
        assert_eq!(res.requeued, 3);
        // uaddr1 should now have 0 non-woken waiters (2 woken, 3 requeued).
        assert_eq!(t.count_on(0x1000), 0);
        // uaddr2 should have 3 waiters.
        assert_eq!(t.count_on(0x2000), 3);
    }

    #[test]
    fn requeue_nr_wake_zero_moves_all() {
        let mut t = WaiterTable::new();
        add_waiters(&mut t, 0x1000, 4);

        let res = do_futex_requeue(&mut t, 0x1000, 0x2000, 0, 4, FUTEX_SIZE_U32).unwrap();
        assert_eq!(res.woken, 0);
        assert_eq!(res.requeued, 4);
        assert_eq!(t.count_on(0x1000), 0);
        assert_eq!(t.count_on(0x2000), 4);
    }

    #[test]
    fn requeue_capped_by_available() {
        let mut t = WaiterTable::new();
        add_waiters(&mut t, 0x3000, 2);

        // Ask to requeue 100, only 2 available.
        let res = do_futex_requeue(&mut t, 0x3000, 0x4000, 0, 100, FUTEX_SIZE_U32).unwrap();
        assert_eq!(res.requeued, 2);
    }

    #[test]
    fn requeue_null_uaddr1_rejected() {
        let mut t = WaiterTable::new();
        assert_eq!(
            do_futex_requeue(&mut t, 0, 0x2000, 1, 1, FUTEX_SIZE_U32),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn requeue_null_uaddr2_rejected() {
        let mut t = WaiterTable::new();
        assert_eq!(
            do_futex_requeue(&mut t, 0x1000, 0, 1, 1, FUTEX_SIZE_U32),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn requeue_identical_addrs_rejected() {
        let mut t = WaiterTable::new();
        assert_eq!(
            do_futex_requeue(&mut t, 0x1000, 0x1000, 1, 1, FUTEX_SIZE_U32),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn requeue_unknown_flags_rejected() {
        let mut t = WaiterTable::new();
        assert_eq!(
            do_futex_requeue(&mut t, 0x1000, 0x2000, 1, 1, 0xFFFF_0000),
            Err(Error::InvalidArgument)
        );
    }

    // --- do_futex_cmp_requeue ---

    #[test]
    fn cmp_requeue_succeeds_when_value_matches() {
        let mut t = WaiterTable::new();
        add_waiters(&mut t, 0xA000, 4);

        let res =
            do_futex_cmp_requeue(&mut t, 0xA000, 0xB000, 1, 3, 42, FUTEX_SIZE_U32, 42).unwrap();
        assert_eq!(res.woken, 1);
        assert_eq!(res.requeued, 3);
    }

    #[test]
    fn cmp_requeue_fails_on_value_mismatch() {
        let mut t = WaiterTable::new();
        add_waiters(&mut t, 0xA000, 4);

        assert_eq!(
            do_futex_cmp_requeue(&mut t, 0xA000, 0xB000, 1, 3, 42, FUTEX_SIZE_U32, 99),
            Err(Error::WouldBlock)
        );
        // No waiters should have been moved.
        assert_eq!(t.count_on(0xA000), 4);
        assert_eq!(t.count_on(0xB000), 0);
    }

    #[test]
    fn cmp_requeue_null_addr_rejected() {
        let mut t = WaiterTable::new();
        assert_eq!(
            do_futex_cmp_requeue(&mut t, 0, 0xB000, 1, 1, 0, FUTEX_SIZE_U32, 0),
            Err(Error::InvalidArgument)
        );
    }

    // --- do_futex_cmp_requeue_pi ---

    #[test]
    fn cmp_requeue_pi_wakes_one_requeues_rest() {
        let mut t = WaiterTable::new();
        add_waiters(&mut t, 0xC000, 5);

        let res = do_futex_cmp_requeue_pi(&mut t, 0xC000, 0xD000, 4, 7, FUTEX_SIZE_U32, 7).unwrap();
        assert_eq!(res.woken, 1);
        assert_eq!(res.requeued, 4);
    }

    #[test]
    fn cmp_requeue_pi_value_mismatch_fails() {
        let mut t = WaiterTable::new();
        add_waiters(&mut t, 0xC000, 3);

        assert_eq!(
            do_futex_cmp_requeue_pi(&mut t, 0xC000, 0xD000, 3, 5, FUTEX_SIZE_U32, 99),
            Err(Error::WouldBlock)
        );
    }

    // --- WaiterTable helpers ---

    #[test]
    fn waiter_table_insert_and_count() {
        let mut t = WaiterTable::new();
        add_waiters(&mut t, 0x5000, 3);
        assert_eq!(t.count_on(0x5000), 3);
    }

    #[test]
    fn waiter_table_remove() {
        let mut t = WaiterTable::new();
        t.insert(Waiter {
            uaddr: 0x6000,
            flags: FUTEX_SIZE_U32,
            tid: 99,
            woken: false,
        })
        .unwrap();
        assert_eq!(t.count_on(0x6000), 1);
        t.remove(99, 0x6000);
        assert_eq!(t.count_on(0x6000), 0);
    }

    #[test]
    fn waiter_table_is_woken() {
        let mut t = WaiterTable::new();
        t.insert(Waiter {
            uaddr: 0x7000,
            flags: FUTEX_SIZE_U32,
            tid: 42,
            woken: false,
        })
        .unwrap();
        t.wake(0x7000, 1);
        assert!(t.is_woken(42, 0x7000));
    }

    #[test]
    fn waiter_table_full_returns_oom() {
        let mut t = WaiterTable::new();
        for i in 0..MAX_WAITERS as u32 {
            t.insert(Waiter {
                uaddr: 0x8000,
                flags: 0,
                tid: i,
                woken: false,
            })
            .unwrap();
        }
        assert_eq!(
            t.insert(Waiter {
                uaddr: 0x8000,
                flags: 0,
                tid: 9999,
                woken: false
            }),
            Err(Error::OutOfMemory)
        );
    }
}
