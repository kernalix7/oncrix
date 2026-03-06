// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! New futex API: `futex_waitv(2)`, `futex_wake(2)`, `futex_wait(2)`.
//!
//! The futex2 interface (merged in Linux 5.16) is a cleaner replacement for
//! the original `futex(2)` multiplexer.  Each operation is a discrete syscall
//! with typed arguments and no overloaded `cmd` integer.
//!
//! # Operations
//!
//! | Syscall          | Handler              | Purpose                              |
//! |------------------|----------------------|--------------------------------------|
//! | `futex_wait`     | [`do_futex_wait`]    | Wait on a single futex               |
//! | `futex_wake`     | [`do_futex_wake`]    | Wake up to N waiters on a futex      |
//! | `futex_waitv`    | [`do_futex_waitv`]   | Wait on a vector of futexes (any)    |
//!
//! # Futex sizes
//!
//! The futex2 API introduces an explicit size field so that 8-, 16-, 32-, and
//! 64-bit futexes are supported.  The size is encoded in the low bits of the
//! `flags` argument via [`FUTEX_SIZE_U8`] through [`FUTEX_SIZE_U64`].
//!
//! # NUMA awareness
//!
//! When [`FUTEX_NUMA_FLAG`] is set the hash bucket is chosen per-NUMA-node
//! rather than globally.  This stub records the flag but does not perform
//! real NUMA placement.
//!
//! # References
//!
//! - Linux: `kernel/futex/futex.h`, `kernel/futex/waitwake.c`
//! - Patch series: "futex2: Add new futex interface" (Andre Almeida, 2021)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Futex size flags (encoded in low 2 bits of flags)
// ---------------------------------------------------------------------------

/// Futex value is a `u8`.
pub const FUTEX_SIZE_U8: u32 = 0x00;
/// Futex value is a `u16`.
pub const FUTEX_SIZE_U16: u32 = 0x01;
/// Futex value is a `u32` (the classic Linux futex size).
pub const FUTEX_SIZE_U32: u32 = 0x02;
/// Futex value is a `u64`.
pub const FUTEX_SIZE_U64: u32 = 0x03;

/// Mask to extract the size field from flags.
pub const FUTEX_SIZE_MASK: u32 = 0x03;

// ---------------------------------------------------------------------------
// Futex flags
// ---------------------------------------------------------------------------

/// The futex lives in shared memory (process-shared semantics).
/// Without this flag the futex is private to the process (faster hash).
pub const FUTEX_SHARED_FLAG: u32 = 1 << 3;

/// Enable NUMA-aware hashing: the bucket is selected per NUMA node.
pub const FUTEX_NUMA_FLAG: u32 = 1 << 4;

/// All recognised futex2 flag bits.
const FUTEX_FLAGS_KNOWN: u32 = FUTEX_SIZE_MASK | FUTEX_SHARED_FLAG | FUTEX_NUMA_FLAG;

// ---------------------------------------------------------------------------
// futex_waitv entry (one element of the wait-vector)
// ---------------------------------------------------------------------------

/// A single entry in the `futex_waitv` vector.
///
/// Layout matches `struct futex_waitv` from `include/uapi/linux/futex.h`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FutexWaitv {
    /// Expected value — the wait is aborted if `*uaddr != val`.
    pub val: u64,
    /// User-space address of the futex word.
    pub uaddr: u64,
    /// Flags: size + shared/private + NUMA bits.
    pub flags: u32,
    /// Reserved — must be zero for forward compatibility.
    pub __reserved: u32,
}

impl FutexWaitv {
    /// Construct a new `FutexWaitv` entry.
    pub const fn new(uaddr: u64, val: u64, flags: u32) -> Self {
        Self {
            val,
            uaddr,
            flags,
            __reserved: 0,
        }
    }

    /// Return the futex size encoded in `flags`.
    pub const fn size(&self) -> u32 {
        self.flags & FUTEX_SIZE_MASK
    }

    /// Return `true` if this futex uses process-shared semantics.
    pub const fn is_shared(&self) -> bool {
        self.flags & FUTEX_SHARED_FLAG != 0
    }
}

// ---------------------------------------------------------------------------
// Timeout specification
// ---------------------------------------------------------------------------

/// Clock identifier for timeout arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FutexClock {
    /// `CLOCK_MONOTONIC` — time since an arbitrary point (unaffected by NTP).
    Monotonic,
    /// `CLOCK_REALTIME` — wall-clock time.
    Realtime,
    /// `CLOCK_BOOTTIME` — like monotonic but includes time in suspend.
    Boottime,
}

/// Timeout for a futex wait operation.
#[derive(Debug, Clone, Copy)]
pub struct FutexTimeout {
    /// Deadline in nanoseconds measured on `clock`.
    pub deadline_ns: u64,
    /// Which clock `deadline_ns` is measured on.
    pub clock: FutexClock,
    /// If `true`, `deadline_ns` is a relative duration; if `false`, absolute.
    pub relative: bool,
}

impl FutexTimeout {
    /// Construct an absolute monotonic deadline.
    pub const fn absolute_monotonic(deadline_ns: u64) -> Self {
        Self {
            deadline_ns,
            clock: FutexClock::Monotonic,
            relative: false,
        }
    }

    /// Construct a relative monotonic timeout.
    pub const fn relative_monotonic(duration_ns: u64) -> Self {
        Self {
            deadline_ns: duration_ns,
            clock: FutexClock::Monotonic,
            relative: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Hash bucket abstraction
// ---------------------------------------------------------------------------

/// Number of hash buckets in the futex hash table.
///
/// In the real kernel this is 256 * num_possible_cpus(). Fixed small value
/// for the stub.
pub const FUTEX_HASH_BUCKETS: usize = 256;

/// Index into the global futex hash table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BucketIndex(usize);

impl BucketIndex {
    /// Return the raw index value.
    pub const fn raw(self) -> usize {
        self.0
    }
}

/// Compute the hash bucket index for a futex at `uaddr` with `flags`.
///
/// For private futexes the hash is purely address-based.
/// For shared futexes it would additionally incorporate inode/offset.
///
/// If [`FUTEX_NUMA_FLAG`] is set the hash is mixed with `numa_node` to
/// direct waiters to a NUMA-local bucket range.
pub fn hash_futex(uaddr: u64, flags: u32, numa_node: u32) -> BucketIndex {
    // Multiplicative hash (Knuth).
    let mut h = uaddr.wrapping_mul(0x9e3779b97f4a7c15);
    if flags & FUTEX_SHARED_FLAG != 0 {
        h ^= 0xdeadbeef_cafebabe_u64;
    }
    if flags & FUTEX_NUMA_FLAG != 0 {
        h ^= (numa_node as u64).wrapping_mul(0x6c62272e07bb0142);
    }
    BucketIndex((h as usize) % FUTEX_HASH_BUCKETS)
}

// ---------------------------------------------------------------------------
// Waiter record
// ---------------------------------------------------------------------------

/// Maximum number of concurrent futex waiters tracked by the stub table.
pub const MAX_FUTEX_WAITERS: usize = 128;

/// A record of one thread waiting on a futex.
#[derive(Debug, Clone, Copy)]
pub struct FutexWaiter {
    /// User-space address of the futex word.
    pub uaddr: u64,
    /// The value that was expected at wait time.
    pub expected_val: u64,
    /// Hash bucket this waiter is queued in.
    pub bucket: BucketIndex,
    /// Flags with which the wait was registered.
    pub flags: u32,
    /// Synthetic thread id of the waiting thread.
    pub tid: u32,
    /// Whether this waiter has been woken.
    pub woken: bool,
}

/// The global futex waiter table (flat array).
pub struct FutexTable {
    waiters: [Option<FutexWaiter>; MAX_FUTEX_WAITERS],
    count: usize,
}

impl FutexTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            waiters: [const { None }; MAX_FUTEX_WAITERS],
            count: 0,
        }
    }

    /// Insert a waiter record.
    ///
    /// Returns `Err(OutOfMemory)` if the table is full.
    pub fn insert(&mut self, waiter: FutexWaiter) -> Result<()> {
        for slot in self.waiters.iter_mut() {
            if slot.is_none() {
                *slot = Some(waiter);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove the waiter for `tid` on `uaddr`.
    pub fn remove(&mut self, tid: u32, uaddr: u64) {
        for slot in self.waiters.iter_mut() {
            if slot
                .as_ref()
                .map(|w| w.tid == tid && w.uaddr == uaddr)
                .unwrap_or(false)
            {
                *slot = None;
                self.count -= 1;
                return;
            }
        }
    }

    /// Wake up to `nr_wake` waiters on `uaddr` in the given bucket.
    ///
    /// Returns the number of waiters actually woken.
    pub fn wake(&mut self, uaddr: u64, bucket: BucketIndex, nr_wake: u32) -> u32 {
        let mut woken = 0u32;
        for slot in self.waiters.iter_mut() {
            if woken >= nr_wake {
                break;
            }
            if let Some(w) = slot {
                if w.uaddr == uaddr && w.bucket == bucket && !w.woken {
                    w.woken = true;
                    woken += 1;
                }
            }
        }
        woken
    }

    /// Return whether a specific waiter (tid, uaddr) has been woken.
    pub fn is_woken(&self, tid: u32, uaddr: u64) -> bool {
        self.waiters
            .iter()
            .filter_map(|s| s.as_ref())
            .any(|w| w.tid == tid && w.uaddr == uaddr && w.woken)
    }

    /// Return the total number of waiters currently in the table.
    pub const fn count(&self) -> usize {
        self.count
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate futex flags: no unknown bits, valid size encoding.
fn validate_flags(flags: u32) -> Result<()> {
    if flags & !FUTEX_FLAGS_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate that `uaddr` is naturally aligned for the given futex size.
fn validate_alignment(uaddr: u64, flags: u32) -> Result<()> {
    let align = match flags & FUTEX_SIZE_MASK {
        FUTEX_SIZE_U8 => 1u64,
        FUTEX_SIZE_U16 => 2,
        FUTEX_SIZE_U32 => 4,
        FUTEX_SIZE_U64 => 8,
        _ => return Err(Error::InvalidArgument),
    };
    if uaddr % align != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// do_futex_wait
// ---------------------------------------------------------------------------

/// Handler for `futex_wait(2)`.
///
/// Atomically checks that `*uaddr == expected_val` and, if so, suspends
/// the calling thread until woken by a [`do_futex_wake`] call or until
/// the optional `timeout` expires.
///
/// # Arguments
///
/// * `table`       — Global futex waiter table.
/// * `uaddr`       — User-space address of the futex word.
/// * `val`         — Expected value of `*uaddr`.
/// * `mask`        — Bitmask applied before comparison (0 = all bits).
/// * `flags`       — Size + shared/private + NUMA bits.
/// * `timeout`     — Optional deadline; `None` means wait indefinitely.
/// * `tid`         — Calling thread id.
/// * `current_val` — The value currently at `*uaddr` (caller read safely).
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Bad flags, misaligned address.
/// * [`Error::WouldBlock`]      — `*uaddr != expected_val` or zero timeout.
/// * [`Error::OutOfMemory`]     — Waiter table full.
pub fn do_futex_wait(
    table: &mut FutexTable,
    uaddr: u64,
    val: u64,
    mask: u64,
    flags: u32,
    timeout: Option<FutexTimeout>,
    tid: u32,
    current_val: u64,
) -> Result<()> {
    validate_flags(flags)?;
    validate_alignment(uaddr, flags)?;

    if uaddr == 0 {
        return Err(Error::InvalidArgument);
    }

    // Effective comparison mask — 0 means compare all bits.
    let cmp_mask = if mask == 0 { u64::MAX } else { mask };

    // Check the futex value (caller supplies current_val read from user space).
    if current_val & cmp_mask != val & cmp_mask {
        return Err(Error::WouldBlock);
    }

    // Zero timeout expires immediately without queuing.
    if let Some(ref t) = timeout {
        if t.deadline_ns == 0 {
            return Err(Error::WouldBlock);
        }
    }

    let bucket = hash_futex(uaddr, flags, 0);
    let waiter = FutexWaiter {
        uaddr,
        expected_val: val,
        bucket,
        flags,
        tid,
        woken: false,
    };
    table.insert(waiter)
}

// ---------------------------------------------------------------------------
// do_futex_wake
// ---------------------------------------------------------------------------

/// Handler for `futex_wake(2)`.
///
/// Wakes up to `nr_wake` threads waiting on `uaddr`.
///
/// # Arguments
///
/// * `table`   — Global futex waiter table.
/// * `uaddr`   — User-space address of the futex word.
/// * `mask`    — Bitset used to filter which waiters to wake (0 = all).
/// * `nr_wake` — Maximum number of waiters to wake.
/// * `flags`   — Size + shared/private + NUMA bits.
///
/// # Returns
///
/// The number of waiters that were woken.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Bad flags or misaligned/null address.
pub fn do_futex_wake(
    table: &mut FutexTable,
    uaddr: u64,
    _mask: u64,
    nr_wake: u32,
    flags: u32,
) -> Result<u32> {
    validate_flags(flags)?;
    validate_alignment(uaddr, flags)?;

    if uaddr == 0 {
        return Err(Error::InvalidArgument);
    }

    if nr_wake == 0 {
        return Ok(0);
    }

    let bucket = hash_futex(uaddr, flags, 0);
    Ok(table.wake(uaddr, bucket, nr_wake))
}

// ---------------------------------------------------------------------------
// do_futex_waitv
// ---------------------------------------------------------------------------

/// Maximum number of entries in a `futex_waitv` vector (`FUTEX_WAITV_MAX`).
pub const FUTEX_WAITV_MAX: usize = 128;

/// Which futex in the vector caused the wake-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitvResult {
    /// Index into the `waiters` slice that woke this thread.
    pub index: usize,
}

/// Handler for `futex_waitv(2)`.
///
/// Waits on a vector of futexes and returns when any one of them is woken.
///
/// # Arguments
///
/// * `table`   — Global futex waiter table.
/// * `waiters` — Slice of [`FutexWaitv`] entries (max [`FUTEX_WAITV_MAX`]).
/// * `flags`   — Global flags (currently must be zero — reserved).
/// * `timeout` — Optional absolute deadline.
/// * `tid`     — Calling thread id.
/// * `vals`    — Current values at each `uaddr` (caller read safely).
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Too many/few entries, bad flags, reserved
///                                field non-zero, null or misaligned address.
/// * [`Error::WouldBlock`]      — A value mismatch was detected or timeout=0.
/// * [`Error::OutOfMemory`]     — Waiter table full.
pub fn do_futex_waitv(
    table: &mut FutexTable,
    waiters: &[FutexWaitv],
    flags: u32,
    timeout: Option<FutexTimeout>,
    tid: u32,
    vals: &[u64],
) -> Result<WaitvResult> {
    // Top-level flags must be zero (reserved).
    if flags != 0 {
        return Err(Error::InvalidArgument);
    }

    if waiters.is_empty() || waiters.len() > FUTEX_WAITV_MAX {
        return Err(Error::InvalidArgument);
    }

    if vals.len() != waiters.len() {
        return Err(Error::InvalidArgument);
    }

    // Validate all entries atomically before queuing any waiter.
    for (i, w) in waiters.iter().enumerate() {
        validate_flags(w.flags)?;
        if w.uaddr == 0 {
            return Err(Error::InvalidArgument);
        }
        validate_alignment(w.uaddr, w.flags)?;
        if w.__reserved != 0 {
            return Err(Error::InvalidArgument);
        }
        // Value mismatch: abort entire wait.
        if vals[i] != w.val {
            return Err(Error::WouldBlock);
        }
    }

    // Zero timeout expires immediately.
    if let Some(ref t) = timeout {
        if t.deadline_ns == 0 {
            return Err(Error::WouldBlock);
        }
    }

    // Enqueue one waiter per entry using a per-entry tid offset.
    let base_tid = tid.wrapping_mul(1000);
    for (i, w) in waiters.iter().enumerate() {
        let bucket = hash_futex(w.uaddr, w.flags, 0);
        let waiter = FutexWaiter {
            uaddr: w.uaddr,
            expected_val: w.val,
            bucket,
            flags: w.flags,
            tid: base_tid.wrapping_add(i as u32),
            woken: false,
        };
        if let Err(e) = table.insert(waiter) {
            // Clean up already-inserted waiters on failure.
            for j in 0..i {
                table.remove(base_tid.wrapping_add(j as u32), waiters[j].uaddr);
            }
            return Err(e);
        }
    }

    // Stub: all waiters enqueued; report index 0 as the triggered entry.
    Ok(WaitvResult { index: 0 })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- hash_futex ---

    #[test]
    fn hash_within_bounds() {
        let b = hash_futex(0xDEAD_BEEF_0000u64, 0, 0);
        assert!(b.raw() < FUTEX_HASH_BUCKETS);
    }

    #[test]
    fn hash_private_and_shared_computed() {
        let _ = hash_futex(0x1000, 0, 0);
        let _ = hash_futex(0x1000, FUTEX_SHARED_FLAG, 0);
        let _ = hash_futex(0x1000, FUTEX_NUMA_FLAG, 1);
    }

    // --- validate_flags ---

    #[test]
    fn unknown_flag_bits_rejected() {
        assert_eq!(validate_flags(0xFFFF_FF00), Err(Error::InvalidArgument));
    }

    #[test]
    fn valid_flag_combinations_accepted() {
        assert_eq!(validate_flags(FUTEX_SIZE_U32), Ok(()));
        assert_eq!(validate_flags(FUTEX_SIZE_U64 | FUTEX_SHARED_FLAG), Ok(()));
        assert_eq!(
            validate_flags(FUTEX_SIZE_U32 | FUTEX_SHARED_FLAG | FUTEX_NUMA_FLAG),
            Ok(())
        );
    }

    // --- validate_alignment ---

    #[test]
    fn u32_must_be_4_byte_aligned() {
        assert_eq!(validate_alignment(0x1000, FUTEX_SIZE_U32), Ok(()));
        assert_eq!(
            validate_alignment(0x1002, FUTEX_SIZE_U32),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn u64_must_be_8_byte_aligned() {
        assert_eq!(validate_alignment(0x2000, FUTEX_SIZE_U64), Ok(()));
        assert_eq!(
            validate_alignment(0x2004, FUTEX_SIZE_U64),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn u8_any_address_valid() {
        assert_eq!(validate_alignment(0x1001, FUTEX_SIZE_U8), Ok(()));
    }

    // --- do_futex_wait ---

    #[test]
    fn wait_succeeds_when_value_matches() {
        let mut t = FutexTable::new();
        let r = do_futex_wait(&mut t, 0x1000, 42, 0, FUTEX_SIZE_U32, None, 1, 42);
        assert_eq!(r, Ok(()));
        assert_eq!(t.count(), 1);
    }

    #[test]
    fn wait_wouldblock_on_value_mismatch() {
        let mut t = FutexTable::new();
        let r = do_futex_wait(&mut t, 0x1000, 42, 0, FUTEX_SIZE_U32, None, 1, 99);
        assert_eq!(r, Err(Error::WouldBlock));
        assert_eq!(t.count(), 0);
    }

    #[test]
    fn wait_rejects_null_uaddr() {
        let mut t = FutexTable::new();
        assert_eq!(
            do_futex_wait(&mut t, 0, 0, 0, FUTEX_SIZE_U32, None, 1, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn wait_rejects_misaligned_u32() {
        let mut t = FutexTable::new();
        assert_eq!(
            do_futex_wait(&mut t, 0x1001, 0, 0, FUTEX_SIZE_U32, None, 1, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn wait_zero_timeout_returns_wouldblock() {
        let mut t = FutexTable::new();
        let to = FutexTimeout::relative_monotonic(0);
        let r = do_futex_wait(&mut t, 0x1000, 5, 0, FUTEX_SIZE_U32, Some(to), 1, 5);
        assert_eq!(r, Err(Error::WouldBlock));
        assert_eq!(t.count(), 0);
    }

    #[test]
    fn wait_mask_comparison() {
        let mut t = FutexTable::new();
        // val=0xFF, current=0x0F, mask=0x0F -> 0x0F & 0x0F == 0xFF & 0x0F: match
        let r = do_futex_wait(&mut t, 0x1000, 0xFF, 0x0F, FUTEX_SIZE_U32, None, 1, 0x0F);
        assert_eq!(r, Ok(()));
    }

    // --- do_futex_wake ---

    #[test]
    fn wake_wakes_waiting_thread() {
        let mut t = FutexTable::new();
        do_futex_wait(&mut t, 0x1000, 1, 0, FUTEX_SIZE_U32, None, 7, 1).unwrap();
        let n = do_futex_wake(&mut t, 0x1000, 0, 1, FUTEX_SIZE_U32).unwrap();
        assert_eq!(n, 1);
        assert!(t.is_woken(7, 0x1000));
    }

    #[test]
    fn wake_nr_zero_wakes_nothing() {
        let mut t = FutexTable::new();
        do_futex_wait(&mut t, 0x1000, 1, 0, FUTEX_SIZE_U32, None, 3, 1).unwrap();
        let n = do_futex_wake(&mut t, 0x1000, 0, 0, FUTEX_SIZE_U32).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn wake_no_waiters_returns_zero() {
        let mut t = FutexTable::new();
        let n = do_futex_wake(&mut t, 0x4000, 0, 10, FUTEX_SIZE_U32).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn wake_rejects_unknown_flags() {
        let mut t = FutexTable::new();
        assert_eq!(
            do_futex_wake(&mut t, 0x1000, 0, 1, 0xFFFF_0000),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn wake_multiple_waiters_limited_by_nr() {
        let mut t = FutexTable::new();
        for tid in 1u32..=5 {
            do_futex_wait(&mut t, 0x2000, 0, 0, FUTEX_SIZE_U32, None, tid, 0).unwrap();
        }
        let n = do_futex_wake(&mut t, 0x2000, 0, 3, FUTEX_SIZE_U32).unwrap();
        assert_eq!(n, 3);
    }

    // --- do_futex_waitv ---

    #[test]
    fn waitv_single_entry_succeeds() {
        let mut t = FutexTable::new();
        let entries = [FutexWaitv::new(0x3000, 10, FUTEX_SIZE_U32)];
        let vals = [10u64];
        let r = do_futex_waitv(&mut t, &entries, 0, None, 1, &vals);
        assert_eq!(r, Ok(WaitvResult { index: 0 }));
        assert_eq!(t.count(), 1);
    }

    #[test]
    fn waitv_mismatch_returns_wouldblock() {
        let mut t = FutexTable::new();
        let entries = [FutexWaitv::new(0x3000, 10, FUTEX_SIZE_U32)];
        let vals = [99u64];
        let r = do_futex_waitv(&mut t, &entries, 0, None, 1, &vals);
        assert_eq!(r, Err(Error::WouldBlock));
        assert_eq!(t.count(), 0);
    }

    #[test]
    fn waitv_rejects_nonzero_top_flags() {
        let mut t = FutexTable::new();
        let entries = [FutexWaitv::new(0x3000, 0, FUTEX_SIZE_U32)];
        let vals = [0u64];
        let r = do_futex_waitv(&mut t, &entries, 1, None, 1, &vals);
        assert_eq!(r, Err(Error::InvalidArgument));
    }

    #[test]
    fn waitv_rejects_empty_slice() {
        let mut t = FutexTable::new();
        let r = do_futex_waitv(&mut t, &[], 0, None, 1, &[]);
        assert_eq!(r, Err(Error::InvalidArgument));
    }

    #[test]
    fn waitv_rejects_reserved_nonzero() {
        let mut t = FutexTable::new();
        let mut entry = FutexWaitv::new(0x4000, 5, FUTEX_SIZE_U32);
        entry.__reserved = 1;
        let r = do_futex_waitv(&mut t, &[entry], 0, None, 1, &[5]);
        assert_eq!(r, Err(Error::InvalidArgument));
    }

    #[test]
    fn waitv_multiple_entries() {
        let mut t = FutexTable::new();
        let entries = [
            FutexWaitv::new(0x5000, 1, FUTEX_SIZE_U32),
            FutexWaitv::new(0x6000, 2, FUTEX_SIZE_U32),
        ];
        let vals = [1u64, 2u64];
        let r = do_futex_waitv(&mut t, &entries, 0, None, 2, &vals);
        assert_eq!(r, Ok(WaitvResult { index: 0 }));
        assert_eq!(t.count(), 2);
    }

    #[test]
    fn waitv_zero_timeout_wouldblock() {
        let mut t = FutexTable::new();
        let entries = [FutexWaitv::new(0x7000, 3, FUTEX_SIZE_U32)];
        let vals = [3u64];
        let to = FutexTimeout::relative_monotonic(0);
        let r = do_futex_waitv(&mut t, &entries, 0, Some(to), 1, &vals);
        assert_eq!(r, Err(Error::WouldBlock));
    }

    #[test]
    fn futex_waitv_size_and_shared_fields() {
        let w = FutexWaitv::new(0x1000, 0, FUTEX_SIZE_U64 | FUTEX_SHARED_FLAG);
        assert_eq!(w.size(), FUTEX_SIZE_U64);
        assert!(w.is_shared());
    }
}
