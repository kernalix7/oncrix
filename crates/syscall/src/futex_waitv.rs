// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `futex_waitv(2)` — wait on multiple futexes simultaneously.
//!
//! This module implements the `futex_waitv` syscall (Linux 5.16+), which
//! allows a thread to block until any one of several futex words changes.
//! It is the vectorized counterpart to `futex_wait` and is the foundation
//! for efficient multi-futex polling (e.g., Wine, Proton, game engines).
//!
//! # Design
//!
//! Each [`FutexWaitvEntry`] carries a user-space address, an expected
//! value, per-entry flags (size, shared/private), and a reserved field
//! for future extensions.  The syscall validates all entries atomically
//! before enqueuing any waiter, so either all are queued or none.
//!
//! # POSIX notes
//!
//! `futex_waitv` is a Linux extension with no POSIX equivalent.  The
//! semantics follow `kernel/futex/waitwake.c` in the Linux kernel.
//!
//! # References
//!
//! - Linux: `include/uapi/linux/futex.h`, `kernel/futex/syscalls.c`
//! - Patch series: "futex2: Add new futex interface" (Andre Almeida)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of entries in a single `futex_waitv` call.
///
/// Matches `FUTEX_WAITV_MAX` from `include/uapi/linux/futex.h`.
pub const FUTEX_WAITV_MAX: usize = 128;

/// Futex value size: 8-bit (`u8`).
pub const FUTEX_32: u32 = 0x02;

/// Private futex flag — futex is not shared across processes.
///
/// When set, the kernel can use a faster process-local hash.
pub const FUTEX_PRIVATE_FLAG: u32 = 128;

/// Futex value size: `u8`.
pub const FUTEX_SIZE_U8: u32 = 0x00;

/// Futex value size: `u16`.
pub const FUTEX_SIZE_U16: u32 = 0x01;

/// Futex value size: `u32` (classic Linux futex size).
pub const FUTEX_SIZE_U32: u32 = 0x02;

/// Futex value size: `u64`.
pub const FUTEX_SIZE_U64: u32 = 0x03;

/// Mask for extracting the size field from flags.
pub const FUTEX_SIZE_MASK: u32 = 0x03;

/// The futex is shared across processes (uses inode-based hashing).
pub const FUTEX_SHARED_FLAG: u32 = 1 << 3;

/// Enable NUMA-aware bucket selection.
pub const FUTEX_NUMA_FLAG: u32 = 1 << 4;

/// All recognised flag bits for per-entry flags.
const ENTRY_FLAGS_KNOWN: u32 = FUTEX_SIZE_MASK | FUTEX_SHARED_FLAG | FUTEX_NUMA_FLAG;

/// Maximum concurrent waiters tracked by the waiter table.
pub const MAX_WAITV_WAITERS: usize = 256;

/// Number of hash buckets for the futex hash table.
pub const FUTEX_HASH_BUCKETS: usize = 256;

// ---------------------------------------------------------------------------
// FutexWaitvEntry — one element of the wait vector
// ---------------------------------------------------------------------------

/// A single entry in the `futex_waitv` vector.
///
/// Layout matches `struct futex_waitv` from `include/uapi/linux/futex.h`.
/// Each entry describes one futex word to watch: its user-space address,
/// the expected value, and per-entry flags controlling size and sharing.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FutexWaitvEntry {
    /// Expected value — the wait is skipped if `*uaddr != val`.
    pub val: u64,
    /// User-space address of the futex word.
    pub uaddr: u64,
    /// Flags: size encoding + shared/private + NUMA bits.
    pub flags: u32,
    /// Reserved for future use — must be zero.
    pub reserved: u32,
}

impl FutexWaitvEntry {
    /// Construct a new entry with the given address, expected value, and flags.
    pub const fn new(uaddr: u64, val: u64, flags: u32) -> Self {
        Self {
            val,
            uaddr,
            flags,
            reserved: 0,
        }
    }

    /// Return the futex size encoded in the flags.
    pub const fn size(&self) -> u32 {
        self.flags & FUTEX_SIZE_MASK
    }

    /// Return `true` if this futex uses process-shared semantics.
    pub const fn is_shared(&self) -> bool {
        self.flags & FUTEX_SHARED_FLAG != 0
    }

    /// Return `true` if this futex is process-private.
    pub const fn is_private(&self) -> bool {
        self.flags & FUTEX_SHARED_FLAG == 0
    }

    /// Return the required alignment in bytes for this entry's size.
    pub const fn required_alignment(&self) -> u64 {
        match self.flags & FUTEX_SIZE_MASK {
            0x00 => 1, // u8
            0x01 => 2, // u16
            0x02 => 4, // u32
            0x03 => 8, // u64
            _ => 1,
        }
    }
}

impl Default for FutexWaitvEntry {
    fn default() -> Self {
        Self {
            val: 0,
            uaddr: 0,
            flags: FUTEX_SIZE_U32,
            reserved: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Timeout specification
// ---------------------------------------------------------------------------

/// Clock source for `futex_waitv` timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitvClock {
    /// `CLOCK_MONOTONIC` — unaffected by NTP adjustments.
    Monotonic,
    /// `CLOCK_REALTIME` — wall-clock time.
    Realtime,
    /// `CLOCK_BOOTTIME` — monotonic including suspend time.
    Boottime,
}

/// Timeout specification for `futex_waitv`.
///
/// The timeout is always interpreted as an absolute deadline on the
/// specified clock (per the Linux `futex_waitv` semantics).
#[derive(Debug, Clone, Copy)]
pub struct WaitvTimeout {
    /// Absolute deadline in nanoseconds on `clock`.
    pub deadline_ns: u64,
    /// Which clock the deadline is measured against.
    pub clock: WaitvClock,
    /// If `true`, `deadline_ns` is a relative duration.
    pub relative: bool,
}

impl WaitvTimeout {
    /// Construct an absolute monotonic deadline.
    pub const fn absolute_monotonic(deadline_ns: u64) -> Self {
        Self {
            deadline_ns,
            clock: WaitvClock::Monotonic,
            relative: false,
        }
    }

    /// Construct a relative monotonic timeout.
    pub const fn relative_monotonic(duration_ns: u64) -> Self {
        Self {
            deadline_ns: duration_ns,
            clock: WaitvClock::Monotonic,
            relative: true,
        }
    }

    /// Return `true` if this timeout has already expired (deadline is zero).
    pub const fn is_expired(&self) -> bool {
        self.deadline_ns == 0
    }
}

// ---------------------------------------------------------------------------
// Hash bucket
// ---------------------------------------------------------------------------

/// Index into the futex hash table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BucketIdx(usize);

impl BucketIdx {
    /// Return the raw bucket index.
    pub const fn raw(self) -> usize {
        self.0
    }
}

/// Compute the hash bucket for a futex at `uaddr` with `flags`.
///
/// Uses a multiplicative hash (Knuth) with mixing for shared and NUMA flags.
pub fn hash_futex_waitv(uaddr: u64, flags: u32, numa_node: u32) -> BucketIdx {
    let mut h = uaddr.wrapping_mul(0x9e3779b97f4a7c15);
    if flags & FUTEX_SHARED_FLAG != 0 {
        h ^= 0xdeadbeef_cafebabe_u64;
    }
    if flags & FUTEX_NUMA_FLAG != 0 {
        h ^= (numa_node as u64).wrapping_mul(0x6c62272e07bb0142);
    }
    BucketIdx((h as usize) % FUTEX_HASH_BUCKETS)
}

// ---------------------------------------------------------------------------
// Waiter record
// ---------------------------------------------------------------------------

/// State of a waiter in the waiter table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaiterState {
    /// Waiter is blocked, waiting to be woken.
    Waiting,
    /// Waiter has been woken by a `futex_wake` call.
    Woken,
    /// Waiter timed out before being woken.
    TimedOut,
}

/// A record of one thread waiting on a futex via `futex_waitv`.
#[derive(Debug, Clone, Copy)]
pub struct WaitvWaiter {
    /// User-space address of the futex word.
    pub uaddr: u64,
    /// The expected value at wait time.
    pub expected_val: u64,
    /// Hash bucket this waiter is queued in.
    pub bucket: BucketIdx,
    /// Per-entry flags (size, shared/private, NUMA).
    pub flags: u32,
    /// Thread ID of the waiting thread.
    pub tid: u32,
    /// Index within the waitv vector that this waiter corresponds to.
    pub waitv_index: u32,
    /// Current state of the waiter.
    pub state: WaiterState,
}

// ---------------------------------------------------------------------------
// WaitvTable — global waiter tracking
// ---------------------------------------------------------------------------

/// Global table tracking all active `futex_waitv` waiters.
///
/// Flat array of optional waiter records. O(n) scan for wake operations.
/// In a production kernel this would be a per-bucket linked list.
pub struct WaitvTable {
    /// Waiter slots.
    waiters: [Option<WaitvWaiter>; MAX_WAITV_WAITERS],
    /// Number of active waiters.
    count: usize,
}

impl WaitvTable {
    /// Create an empty waiter table.
    pub const fn new() -> Self {
        Self {
            waiters: [const { None }; MAX_WAITV_WAITERS],
            count: 0,
        }
    }

    /// Return the number of active waiters.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return `true` if the table has no active waiters.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Insert a waiter record into the table.
    ///
    /// Returns `OutOfMemory` if no free slots remain.
    pub fn insert(&mut self, waiter: WaitvWaiter) -> Result<usize> {
        for (i, slot) in self.waiters.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(waiter);
                self.count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a waiter by its slot index.
    pub fn remove(&mut self, slot_idx: usize) {
        if slot_idx < MAX_WAITV_WAITERS && self.waiters[slot_idx].is_some() {
            self.waiters[slot_idx] = None;
            self.count = self.count.saturating_sub(1);
        }
    }

    /// Remove all waiters belonging to a thread identified by `tid` and
    /// a base tid (for vectorized waits, tid is base_tid + entry_index).
    pub fn remove_range(&mut self, base_tid: u32, count: u32) {
        for slot in self.waiters.iter_mut() {
            if let Some(w) = slot {
                if w.tid >= base_tid && w.tid < base_tid.wrapping_add(count) {
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                }
            }
        }
    }

    /// Wake up to `nr_wake` waiters on `uaddr` in the given bucket.
    ///
    /// Returns the number of waiters actually woken.
    pub fn wake(&mut self, uaddr: u64, bucket: BucketIdx, nr_wake: u32) -> u32 {
        let mut woken = 0u32;
        for slot in self.waiters.iter_mut() {
            if woken >= nr_wake {
                break;
            }
            if let Some(w) = slot {
                if w.uaddr == uaddr && w.bucket == bucket && w.state == WaiterState::Waiting {
                    w.state = WaiterState::Woken;
                    woken += 1;
                }
            }
        }
        woken
    }

    /// Check if any waiter in the given tid range has been woken.
    ///
    /// Returns `Some(waitv_index)` for the first woken waiter found,
    /// or `None` if no waiters have been woken.
    pub fn find_woken(&self, base_tid: u32, count: u32) -> Option<u32> {
        for slot in &self.waiters {
            if let Some(w) = slot {
                if w.tid >= base_tid
                    && w.tid < base_tid.wrapping_add(count)
                    && w.state == WaiterState::Woken
                {
                    return Some(w.waitv_index);
                }
            }
        }
        None
    }

    /// Check if a specific waiter (by tid) has been woken.
    pub fn is_woken(&self, tid: u32) -> bool {
        self.waiters
            .iter()
            .filter_map(|s| s.as_ref())
            .any(|w| w.tid == tid && w.state == WaiterState::Woken)
    }

    /// Mark all waiters in the given tid range as timed out.
    pub fn timeout_range(&mut self, base_tid: u32, count: u32) {
        for slot in self.waiters.iter_mut() {
            if let Some(w) = slot {
                if w.tid >= base_tid
                    && w.tid < base_tid.wrapping_add(count)
                    && w.state == WaiterState::Waiting
                {
                    w.state = WaiterState::TimedOut;
                }
            }
        }
    }
}

impl Default for WaitvTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate per-entry flags: no unknown bits.
fn validate_entry_flags(flags: u32) -> Result<()> {
    if flags & !ENTRY_FLAGS_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate that `uaddr` is naturally aligned for the futex size in `flags`.
fn validate_entry_alignment(uaddr: u64, flags: u32) -> Result<()> {
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

/// Validate a single entry in the waitv vector.
fn validate_entry(entry: &FutexWaitvEntry) -> Result<()> {
    validate_entry_flags(entry.flags)?;
    if entry.uaddr == 0 {
        return Err(Error::InvalidArgument);
    }
    validate_entry_alignment(entry.uaddr, entry.flags)?;
    if entry.reserved != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// WaitvResult
// ---------------------------------------------------------------------------

/// Result of a successful `futex_waitv` call.
///
/// Contains the index of the futex entry that caused the wake-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitvResult {
    /// Index into the original `waiters` slice.
    pub index: usize,
}

// ---------------------------------------------------------------------------
// sys_futex_waitv — the main syscall handler
// ---------------------------------------------------------------------------

/// Handler for `futex_waitv(2)`.
///
/// Blocks the calling thread until any one of the futexes in `entries`
/// is woken, or until the optional `timeout` expires.
///
/// # Arguments
///
/// * `table`   — Global waiter table for tracking blocked threads.
/// * `entries` — Slice of [`FutexWaitvEntry`] describing futexes to wait on.
///               Must contain between 1 and [`FUTEX_WAITV_MAX`] entries.
/// * `flags`   — Global flags (must be zero — reserved for future use).
/// * `timeout` — Optional deadline; `None` means wait indefinitely.
/// * `tid`     — Calling thread ID.
/// * `current_vals` — Current values at each `uaddr`, read safely by caller.
///
/// # Returns
///
/// On success, returns a [`WaitvResult`] containing the index of the
/// entry that caused the wake-up. In this stub implementation, all
/// waiters are enqueued and index 0 is returned.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Empty or oversized vector, non-zero
///   global flags, bad per-entry flags, null/misaligned address, or
///   non-zero reserved field.
/// * [`Error::WouldBlock`] — A value mismatch was detected or the
///   timeout has already expired.
/// * [`Error::OutOfMemory`] — Waiter table is full.
pub fn sys_futex_waitv(
    table: &mut WaitvTable,
    entries: &[FutexWaitvEntry],
    flags: u32,
    timeout: Option<WaitvTimeout>,
    tid: u32,
    current_vals: &[u64],
) -> Result<WaitvResult> {
    // Global flags must be zero (reserved).
    if flags != 0 {
        return Err(Error::InvalidArgument);
    }

    // Validate entry count.
    if entries.is_empty() || entries.len() > FUTEX_WAITV_MAX {
        return Err(Error::InvalidArgument);
    }

    // current_vals must match entries length.
    if current_vals.len() != entries.len() {
        return Err(Error::InvalidArgument);
    }

    // Phase 1: validate all entries atomically before queuing any waiter.
    for (i, entry) in entries.iter().enumerate() {
        validate_entry(entry)?;

        // Value mismatch — abort entire wait.
        if current_vals[i] != entry.val {
            return Err(Error::WouldBlock);
        }
    }

    // Expired timeout — return immediately.
    if let Some(ref t) = timeout {
        if t.is_expired() {
            return Err(Error::WouldBlock);
        }
    }

    // Phase 2: enqueue one waiter per entry.
    // Use a per-entry tid offset so each waiter has a unique id.
    let base_tid = tid.wrapping_mul(1000);
    let entry_count = entries.len();
    let mut slot_indices: [usize; FUTEX_WAITV_MAX] = [0; FUTEX_WAITV_MAX];

    for (i, entry) in entries.iter().enumerate() {
        let bucket = hash_futex_waitv(entry.uaddr, entry.flags, 0);
        let waiter = WaitvWaiter {
            uaddr: entry.uaddr,
            expected_val: entry.val,
            bucket,
            flags: entry.flags,
            tid: base_tid.wrapping_add(i as u32),
            waitv_index: i as u32,
            state: WaiterState::Waiting,
        };
        match table.insert(waiter) {
            Ok(idx) => slot_indices[i] = idx,
            Err(e) => {
                // Rollback: remove already-inserted waiters.
                for j in 0..i {
                    table.remove(slot_indices[j]);
                }
                return Err(e);
            }
        }
    }

    // Phase 3: check for wake-ups.
    // In a real kernel, we would schedule out here and be woken by
    // futex_wake on any of the watched addresses.
    // Stub: check if any waiter was woken during insertion.
    if let Some(idx) = table.find_woken(base_tid, entry_count as u32) {
        // Clean up all waiters for this call.
        table.remove_range(base_tid, entry_count as u32);
        return Ok(WaitvResult {
            index: idx as usize,
        });
    }

    // Stub: report index 0 as the triggered entry (all waiters enqueued).
    Ok(WaitvResult { index: 0 })
}

// ---------------------------------------------------------------------------
// Helper: wake a futex_waitv waiter
// ---------------------------------------------------------------------------

/// Wake up to `nr_wake` waiters on the given futex address.
///
/// This is the wake-side counterpart used by `futex_wake` to unblock
/// threads that called `futex_waitv`.
///
/// Returns the number of waiters actually woken.
pub fn wake_waitv(table: &mut WaitvTable, uaddr: u64, flags: u32, nr_wake: u32) -> Result<u32> {
    validate_entry_flags(flags)?;
    if uaddr == 0 {
        return Err(Error::InvalidArgument);
    }
    validate_entry_alignment(uaddr, flags)?;

    if nr_wake == 0 {
        return Ok(0);
    }

    let bucket = hash_futex_waitv(uaddr, flags, 0);
    Ok(table.wake(uaddr, bucket, nr_wake))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_default_is_u32() {
        let e = FutexWaitvEntry::default();
        assert_eq!(e.size(), FUTEX_SIZE_U32);
        assert!(!e.is_shared());
        assert!(e.is_private());
    }

    #[test]
    fn entry_alignment_checks() {
        let e8 = FutexWaitvEntry::new(0x1001, 0, FUTEX_SIZE_U8);
        assert_eq!(e8.required_alignment(), 1);
        let e32 = FutexWaitvEntry::new(0x1000, 0, FUTEX_SIZE_U32);
        assert_eq!(e32.required_alignment(), 4);
        let e64 = FutexWaitvEntry::new(0x2000, 0, FUTEX_SIZE_U64);
        assert_eq!(e64.required_alignment(), 8);
    }

    #[test]
    fn hash_within_bounds() {
        let b = hash_futex_waitv(0xDEAD_BEEF_0000, 0, 0);
        assert!(b.raw() < FUTEX_HASH_BUCKETS);
    }

    #[test]
    fn validate_entry_rejects_null_uaddr() {
        let e = FutexWaitvEntry::new(0, 0, FUTEX_SIZE_U32);
        assert_eq!(validate_entry(&e), Err(Error::InvalidArgument));
    }

    #[test]
    fn validate_entry_rejects_misaligned() {
        let e = FutexWaitvEntry::new(0x1001, 0, FUTEX_SIZE_U32);
        assert_eq!(validate_entry(&e), Err(Error::InvalidArgument));
    }

    #[test]
    fn validate_entry_rejects_nonzero_reserved() {
        let mut e = FutexWaitvEntry::new(0x1000, 0, FUTEX_SIZE_U32);
        e.reserved = 1;
        assert_eq!(validate_entry(&e), Err(Error::InvalidArgument));
    }

    #[test]
    fn validate_entry_rejects_unknown_flags() {
        let e = FutexWaitvEntry::new(0x1000, 0, 0xFFFF_0000);
        assert_eq!(validate_entry(&e), Err(Error::InvalidArgument));
    }

    #[test]
    fn waitv_single_entry_succeeds() {
        let mut t = WaitvTable::new();
        let entries = [FutexWaitvEntry::new(0x1000, 42, FUTEX_SIZE_U32)];
        let vals = [42u64];
        let r = sys_futex_waitv(&mut t, &entries, 0, None, 1, &vals);
        assert_eq!(r, Ok(WaitvResult { index: 0 }));
        assert!(t.count() >= 1);
    }

    #[test]
    fn waitv_value_mismatch_returns_wouldblock() {
        let mut t = WaitvTable::new();
        let entries = [FutexWaitvEntry::new(0x1000, 42, FUTEX_SIZE_U32)];
        let vals = [99u64];
        let r = sys_futex_waitv(&mut t, &entries, 0, None, 1, &vals);
        assert_eq!(r, Err(Error::WouldBlock));
    }

    #[test]
    fn waitv_empty_slice_rejected() {
        let mut t = WaitvTable::new();
        let r = sys_futex_waitv(&mut t, &[], 0, None, 1, &[]);
        assert_eq!(r, Err(Error::InvalidArgument));
    }

    #[test]
    fn waitv_nonzero_global_flags_rejected() {
        let mut t = WaitvTable::new();
        let entries = [FutexWaitvEntry::new(0x1000, 0, FUTEX_SIZE_U32)];
        let vals = [0u64];
        let r = sys_futex_waitv(&mut t, &entries, 1, None, 1, &vals);
        assert_eq!(r, Err(Error::InvalidArgument));
    }

    #[test]
    fn waitv_expired_timeout_returns_wouldblock() {
        let mut t = WaitvTable::new();
        let entries = [FutexWaitvEntry::new(0x1000, 5, FUTEX_SIZE_U32)];
        let vals = [5u64];
        let to = WaitvTimeout::relative_monotonic(0);
        let r = sys_futex_waitv(&mut t, &entries, 0, Some(to), 1, &vals);
        assert_eq!(r, Err(Error::WouldBlock));
    }

    #[test]
    fn waitv_multiple_entries() {
        let mut t = WaitvTable::new();
        let entries = [
            FutexWaitvEntry::new(0x2000, 1, FUTEX_SIZE_U32),
            FutexWaitvEntry::new(0x3000, 2, FUTEX_SIZE_U64),
            FutexWaitvEntry::new(0x4000, 3, FUTEX_SIZE_U32 | FUTEX_SHARED_FLAG),
        ];
        let vals = [1u64, 2, 3];
        let r = sys_futex_waitv(&mut t, &entries, 0, None, 5, &vals);
        assert!(r.is_ok());
        assert!(t.count() >= 3);
    }

    #[test]
    fn waitv_mismatched_vals_len_rejected() {
        let mut t = WaitvTable::new();
        let entries = [FutexWaitvEntry::new(0x1000, 1, FUTEX_SIZE_U32)];
        let vals = [1u64, 2];
        let r = sys_futex_waitv(&mut t, &entries, 0, None, 1, &vals);
        assert_eq!(r, Err(Error::InvalidArgument));
    }

    #[test]
    fn wake_waitv_wakes_waiter() {
        let mut t = WaitvTable::new();
        let entries = [FutexWaitvEntry::new(0x5000, 10, FUTEX_SIZE_U32)];
        let vals = [10u64];
        let _ = sys_futex_waitv(&mut t, &entries, 0, None, 7, &vals);

        let woken = wake_waitv(&mut t, 0x5000, FUTEX_SIZE_U32, 1);
        assert_eq!(woken, Ok(1));
    }

    #[test]
    fn wake_waitv_rejects_null_uaddr() {
        let mut t = WaitvTable::new();
        assert_eq!(
            wake_waitv(&mut t, 0, FUTEX_SIZE_U32, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn table_remove_range() {
        let mut t = WaitvTable::new();
        let entries = [
            FutexWaitvEntry::new(0x1000, 1, FUTEX_SIZE_U32),
            FutexWaitvEntry::new(0x2000, 2, FUTEX_SIZE_U32),
        ];
        let vals = [1u64, 2];
        let _ = sys_futex_waitv(&mut t, &entries, 0, None, 3, &vals);
        let base = 3u32.wrapping_mul(1000);
        t.remove_range(base, 2);
        assert_eq!(t.count(), 0);
    }

    #[test]
    fn timeout_is_expired() {
        let t = WaitvTimeout::relative_monotonic(0);
        assert!(t.is_expired());
        let t2 = WaitvTimeout::absolute_monotonic(100);
        assert!(!t2.is_expired());
    }
}
