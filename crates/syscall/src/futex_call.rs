// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `futex` syscall handler.
//!
//! Implements `futex(2)` per Linux ABI.
//! Futexes (Fast Userspace muTEXes) provide efficient blocking primitives.
//! The primary operations are:
//! - `FUTEX_WAIT`: atomically verify *uaddr == val, then sleep.
//! - `FUTEX_WAKE`: wake up to `val` waiters on uaddr.
//! - `FUTEX_REQUEUE`: wake some waiters, requeue others to a different uaddr.
//! - `FUTEX_CMP_REQUEUE`: like REQUEUE but with an atomic comparison.
//!
//! # References
//!
//! - Linux man pages: `futex(2)`, `futex(7)`
//! - Linux include/uapi/linux/futex.h

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Futex operation constants
// ---------------------------------------------------------------------------

/// Wait on the futex (block if *uaddr == val).
pub const FUTEX_WAIT: u32 = 0;
/// Wake up to `val` waiters on the futex.
pub const FUTEX_WAKE: u32 = 1;
/// POSIX realtime clock wait.
pub const FUTEX_WAIT_BITSET: u32 = 9;
/// Wake with bitmask matching.
pub const FUTEX_WAKE_BITSET: u32 = 10;
/// Requeue: wake `val` waiters, move up to `val2` to uaddr2.
pub const FUTEX_REQUEUE: u32 = 3;
/// CMP_REQUEUE: like REQUEUE, but verify *uaddr == val3 first.
pub const FUTEX_CMP_REQUEUE: u32 = 4;

/// Modifier: use process-private futex (no shared memory support needed).
pub const FUTEX_PRIVATE_FLAG: u32 = 128;

/// Mask to extract the base operation (without PRIVATE flag).
const FUTEX_OP_MASK: u32 = 0x7F;

/// FUTEX_BITSET_MATCH_ANY: bitmask that matches all waiters.
pub const FUTEX_BITSET_MATCH_ANY: u32 = 0xFFFF_FFFF;

// ---------------------------------------------------------------------------
// FutexOp — decoded futex operation
// ---------------------------------------------------------------------------

/// A decoded futex operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FutexOp {
    /// `FUTEX_WAIT`: block until `*uaddr == val` or timeout.
    Wait { val: u32, bitset: u32 },
    /// `FUTEX_WAKE`: wake up to `val` waiters.
    Wake { val: u32, bitset: u32 },
    /// `FUTEX_REQUEUE`: wake `val` waiters; requeue up to `val2` to `uaddr2`.
    Requeue { wake_count: u32, requeue_count: u32 },
    /// `FUTEX_CMP_REQUEUE`: compare *uaddr == val3, then requeue.
    CmpRequeue {
        wake_count: u32,
        requeue_count: u32,
        cmp_val: u32,
    },
}

impl FutexOp {
    /// Decode a raw `op` argument into a `FutexOp`.
    ///
    /// Returns `Err(InvalidArgument)` for unknown operations.
    pub fn decode(op: u32, val: u32, val2: u32, val3: u32) -> Result<Self> {
        let base = op & FUTEX_OP_MASK;
        match base {
            FUTEX_WAIT => Ok(FutexOp::Wait {
                val,
                bitset: FUTEX_BITSET_MATCH_ANY,
            }),
            FUTEX_WAKE => Ok(FutexOp::Wake {
                val,
                bitset: FUTEX_BITSET_MATCH_ANY,
            }),
            FUTEX_WAIT_BITSET => Ok(FutexOp::Wait { val, bitset: val3 }),
            FUTEX_WAKE_BITSET => Ok(FutexOp::Wake { val, bitset: val3 }),
            FUTEX_REQUEUE => Ok(FutexOp::Requeue {
                wake_count: val,
                requeue_count: val2,
            }),
            FUTEX_CMP_REQUEUE => Ok(FutexOp::CmpRequeue {
                wake_count: val,
                requeue_count: val2,
                cmp_val: val3,
            }),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ---------------------------------------------------------------------------
// Timespec
// ---------------------------------------------------------------------------

/// POSIX `struct timespec` for futex timeout.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timespec {
    /// Seconds.
    pub tv_sec: i64,
    /// Nanoseconds (0 .. 999_999_999).
    pub tv_nsec: i64,
}

impl Timespec {
    /// Validate that nanoseconds are in range.
    pub fn validate(&self) -> Result<()> {
        if self.tv_sec < 0 || self.tv_nsec < 0 || self.tv_nsec >= 1_000_000_000 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FutexWaiter — entry in the futex wait queue
// ---------------------------------------------------------------------------

/// A single waiter blocked on a futex.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FutexWaiter {
    /// User-space address of the futex being waited on.
    pub uaddr: u64,
    /// The bitset used to match wake operations.
    pub bitset: u32,
    /// Thread identifier of the waiting task.
    pub tid: u64,
}

impl FutexWaiter {
    /// Return `true` if this waiter's bitset matches the wake bitmask.
    pub const fn matches(&self, wake_bitset: u32) -> bool {
        self.bitset & wake_bitset != 0
    }
}

// ---------------------------------------------------------------------------
// FutexBucket — hash bucket for the futex table
// ---------------------------------------------------------------------------

/// A bucket in the global futex hash table.
///
/// A production implementation uses a fixed-size hash table indexed by
/// (physical page address XOR offset). This stub uses a simple array.
#[derive(Debug)]
pub struct FutexBucket<'a> {
    /// Slice of waiters in this bucket.
    pub waiters: &'a [FutexWaiter],
}

impl<'a> FutexBucket<'a> {
    /// Create a new bucket from an existing waiter slice.
    pub const fn new(waiters: &'a [FutexWaiter]) -> Self {
        Self { waiters }
    }

    /// Count waiters on `uaddr` whose bitset matches `wake_bitset`.
    pub fn count_matching(&self, uaddr: u64, wake_bitset: u32) -> usize {
        self.waiters
            .iter()
            .filter(|w| w.uaddr == uaddr && w.matches(wake_bitset))
            .count()
    }
}

// ---------------------------------------------------------------------------
// FutexResult
// ---------------------------------------------------------------------------

/// Result of a futex operation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FutexResult {
    /// Number of waiters woken.
    pub woken: u32,
    /// Number of waiters requeued (for REQUEUE / CMP_REQUEUE).
    pub requeued: u32,
}

// ---------------------------------------------------------------------------
// Futex word simulation
// ---------------------------------------------------------------------------

/// Simulate reading the futex word at `uaddr`.
///
/// A production implementation would use a privileged read with
/// proper error handling for invalid user pointers.
fn read_futex_word(uaddr: u64, mem: &[u32]) -> Option<u32> {
    // Treat the slice as byte-addressed 32-bit words.
    let idx = (uaddr as usize) / 4;
    mem.get(idx).copied()
}

// ---------------------------------------------------------------------------
// Operation handlers
// ---------------------------------------------------------------------------

/// Handle `FUTEX_WAIT` / `FUTEX_WAIT_BITSET`.
fn handle_wait(
    uaddr: u64,
    val: u32,
    bitset: u32,
    timeout: Option<&Timespec>,
    mem: &[u32],
) -> Result<FutexResult> {
    if bitset == 0 {
        return Err(Error::InvalidArgument);
    }
    if let Some(ts) = timeout {
        ts.validate()?;
    }
    // Atomically check *uaddr == val.
    match read_futex_word(uaddr, mem) {
        None => Err(Error::InvalidArgument),
        Some(current) if current != val => {
            // Value changed before we could sleep — return EAGAIN.
            Err(Error::WouldBlock)
        }
        Some(_) => {
            // Stub: real implementation enqueues the current thread and
            // calls schedule(). Returns 0 on successful wake.
            Err(Error::NotImplemented)
        }
    }
}

/// Handle `FUTEX_WAKE` / `FUTEX_WAKE_BITSET`.
fn handle_wake(uaddr: u64, val: u32, bitset: u32, bucket: &FutexBucket<'_>) -> Result<FutexResult> {
    if bitset == 0 {
        return Err(Error::InvalidArgument);
    }
    let available = bucket.count_matching(uaddr, bitset);
    let woken = (val as usize).min(available) as u32;
    // Stub: real implementation calls try_to_wake_up() for each waiter.
    Ok(FutexResult { woken, requeued: 0 })
}

/// Handle `FUTEX_REQUEUE`.
fn handle_requeue(
    uaddr: u64,
    uaddr2: u64,
    wake_count: u32,
    requeue_count: u32,
    bucket: &FutexBucket<'_>,
) -> Result<FutexResult> {
    let available = bucket.count_matching(uaddr, FUTEX_BITSET_MATCH_ANY);
    let woken = (wake_count as usize).min(available) as u32;
    let remaining = available - woken as usize;
    let requeued = (requeue_count as usize).min(remaining) as u32;
    let _ = uaddr2;
    // Stub: real implementation moves waiters from uaddr to uaddr2.
    Ok(FutexResult { woken, requeued })
}

/// Handle `FUTEX_CMP_REQUEUE`.
fn handle_cmp_requeue(
    uaddr: u64,
    uaddr2: u64,
    wake_count: u32,
    requeue_count: u32,
    cmp_val: u32,
    bucket: &FutexBucket<'_>,
    mem: &[u32],
) -> Result<FutexResult> {
    // Atomically verify *uaddr == cmp_val.
    match read_futex_word(uaddr, mem) {
        None => Err(Error::InvalidArgument),
        Some(current) if current != cmp_val => Err(Error::WouldBlock),
        Some(_) => handle_requeue(uaddr, uaddr2, wake_count, requeue_count, bucket),
    }
}

// ---------------------------------------------------------------------------
// Public syscall handler
// ---------------------------------------------------------------------------

/// `futex` — fast userspace mutex primitive.
///
/// Dispatches to the appropriate futex operation handler based on `op`.
///
/// # Errors
///
/// | `Error`           | Condition                                        |
/// |-------------------|--------------------------------------------------|
/// | `InvalidArgument` | Unknown `op`, zero bitset, or invalid timeout    |
/// | `WouldBlock`      | FUTEX_WAIT: `*uaddr != val`; CMP_REQUEUE mismatch|
/// | `BadAddress`      | `uaddr` is not accessible                        |
///
/// Reference: Linux futex(2).
pub fn do_futex(
    uaddr: u64,
    op: u32,
    val: u32,
    timeout: Option<&Timespec>,
    uaddr2: u64,
    val3: u32,
    bucket: &FutexBucket<'_>,
    mem: &[u32],
) -> Result<FutexResult> {
    // Extract val2 from timeout pointer (Linux reuses this parameter slot).
    // For simplicity, val2 = 0 when timeout is None.
    let val2 = 0u32;

    let futex_op = FutexOp::decode(op, val, val2, val3)?;

    match futex_op {
        FutexOp::Wait {
            val: expected,
            bitset,
        } => handle_wait(uaddr, expected, bitset, timeout, mem),
        FutexOp::Wake { val: count, bitset } => handle_wake(uaddr, count, bitset, bucket),
        FutexOp::Requeue {
            wake_count,
            requeue_count,
        } => handle_requeue(uaddr, uaddr2, wake_count, requeue_count, bucket),
        FutexOp::CmpRequeue {
            wake_count,
            requeue_count,
            cmp_val,
        } => handle_cmp_requeue(
            uaddr,
            uaddr2,
            wake_count,
            requeue_count,
            cmp_val,
            bucket,
            mem,
        ),
    }
}
