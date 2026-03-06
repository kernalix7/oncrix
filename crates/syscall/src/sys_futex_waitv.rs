// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `futex_waitv(2)` syscall handler — wait on multiple futex addresses.
//!
//! `futex_waitv` allows a thread to block until any one of several futex
//! words changes value.  It is the vectorised successor to `FUTEX_WAIT` and
//! is used by Wine/Proton, game engines, and runtimes that need to wait on
//! multiple synchronisation objects without spinning.
//!
//! # Syscall signature
//!
//! ```text
//! long futex_waitv(struct futex_waitv *waiters, unsigned int nr_futexes,
//!                  unsigned int flags, struct timespec *timeout,
//!                  clockid_t clockid);
//! ```
//!
//! # Per-entry flags
//!
//! Each [`FutexWaitvEntry`] carries its own flags controlling the futex
//! word size (`FUTEX_SIZE_U8` … `FUTEX_SIZE_U64`) and whether the futex
//! is process-private (`FUTEX_PRIVATE_FLAG`) or shared.
//!
//! # Timeout
//!
//! The timeout is always an **absolute** deadline.  `CLOCK_MONOTONIC` or
//! `CLOCK_REALTIME` are supported.  A zero deadline means "already expired".
//!
//! # Return value
//!
//! On success: the **index** (0-based) of the futex entry whose value
//! changed and woke the thread.
//! On failure: a negative errno.
//!
//! # References
//!
//! - Linux: `kernel/futex/syscalls.c`, `include/uapi/linux/futex.h`
//! - Introduced Linux 5.16 (André Almeida)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of futex entries in a single call (matches Linux).
pub const FUTEX_WAITV_MAX: usize = 128;

/// Futex word size: 8-bit.
pub const FUTEX_SIZE_U8: u32 = 0x00;
/// Futex word size: 16-bit.
pub const FUTEX_SIZE_U16: u32 = 0x01;
/// Futex word size: 32-bit (classic Linux futex).
pub const FUTEX_SIZE_U32: u32 = 0x02;
/// Futex word size: 64-bit.
pub const FUTEX_SIZE_U64: u32 = 0x03;
/// Mask to extract the size field from per-entry flags.
pub const FUTEX_SIZE_MASK: u32 = 0x03;

/// Marks the futex as process-private (faster, no inode lookup).
pub const FUTEX_PRIVATE_FLAG: u32 = 128;

/// Marks the futex as process-shared (uses inode-based hash).
pub const FUTEX_SHARED_FLAG: u32 = 1 << 3;

/// All valid per-entry flag bits.
const ENTRY_FLAGS_VALID: u32 = FUTEX_SIZE_MASK | FUTEX_PRIVATE_FLAG | FUTEX_SHARED_FLAG;

// Global flags for `futex_waitv` are currently reserved and must be zero.

// ---------------------------------------------------------------------------
// Clock ID
// ---------------------------------------------------------------------------

/// Clock source for the `futex_waitv` timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FutexClock {
    /// `CLOCK_MONOTONIC` (value 1) — unaffected by NTP adjustments.
    Monotonic,
    /// `CLOCK_REALTIME` (value 0) — wall-clock time.
    Realtime,
    /// `CLOCK_BOOTTIME` (value 7) — monotonic including suspend.
    Boottime,
}

impl FutexClock {
    /// Parse a raw `clockid_t` value.
    ///
    /// Returns `InvalidArgument` for unrecognised clock IDs.
    pub fn from_clockid(id: i32) -> Result<Self> {
        match id {
            0 => Ok(Self::Realtime),
            1 => Ok(Self::Monotonic),
            7 => Ok(Self::Boottime),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ---------------------------------------------------------------------------
// FutexWaitvEntry — one entry in the wait vector
// ---------------------------------------------------------------------------

/// A single futex wait specification.
///
/// ABI-compatible with `struct futex_waitv` from
/// `include/uapi/linux/futex.h`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FutexWaitvEntry {
    /// Expected value at `uaddr`.  If `*uaddr != val` the entry is skipped
    /// (value mismatch → `EAGAIN`).
    pub val: u64,
    /// User-space address of the futex word.
    pub uaddr: u64,
    /// Per-entry flags (size + private/shared).
    pub flags: u32,
    /// Reserved — must be zero.
    pub reserved: u32,
}

impl FutexWaitvEntry {
    /// Construct an entry for a U32 private futex.
    pub const fn new_u32_private(uaddr: u64, val: u32) -> Self {
        Self {
            val: val as u64,
            uaddr,
            flags: FUTEX_SIZE_U32 | FUTEX_PRIVATE_FLAG,
            reserved: 0,
        }
    }

    /// Construct an entry with explicit flags.
    pub const fn new(uaddr: u64, val: u64, flags: u32) -> Self {
        Self {
            val,
            uaddr,
            flags,
            reserved: 0,
        }
    }

    /// Return the byte size of the futex word.
    pub const fn word_bytes(&self) -> u64 {
        match self.flags & FUTEX_SIZE_MASK {
            FUTEX_SIZE_U8 => 1,
            FUTEX_SIZE_U16 => 2,
            FUTEX_SIZE_U32 => 4,
            _ => 8, // FUTEX_SIZE_U64
        }
    }

    /// Return `true` if the futex address is naturally aligned.
    pub const fn is_aligned(&self) -> bool {
        let align = self.word_bytes();
        self.uaddr % align == 0
    }

    /// Return `true` if the futex is process-private.
    pub const fn is_private(&self) -> bool {
        self.flags & FUTEX_PRIVATE_FLAG != 0
    }
}

impl Default for FutexWaitvEntry {
    fn default() -> Self {
        Self::new_u32_private(0, 0)
    }
}

// ---------------------------------------------------------------------------
// WaitvTimeout
// ---------------------------------------------------------------------------

/// Absolute deadline for a `futex_waitv` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitvTimeout {
    /// Absolute deadline in nanoseconds on `clock`.
    pub deadline_ns: u64,
    /// Clock against which the deadline is measured.
    pub clock: FutexClock,
}

impl WaitvTimeout {
    /// Construct a monotonic absolute timeout.
    pub const fn monotonic(deadline_ns: u64) -> Self {
        Self {
            deadline_ns,
            clock: FutexClock::Monotonic,
        }
    }

    /// Return `true` if the deadline is zero (already expired).
    pub const fn is_expired(&self) -> bool {
        self.deadline_ns == 0
    }
}

// ---------------------------------------------------------------------------
// WaiterSlot — active waiter record
// ---------------------------------------------------------------------------

/// State of a queued waiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaiterState {
    /// Waiting to be woken.
    Pending,
    /// Woken by a `futex_wake` on this address.
    Woken,
    /// Timed out before being woken.
    TimedOut,
}

/// Internal record for one queued waiter.
#[derive(Debug, Clone, Copy)]
pub struct WaiterSlot {
    /// User-space address being waited on.
    pub uaddr: u64,
    /// Expected value when the waiter was enqueued.
    pub expected: u64,
    /// Per-entry flags.
    pub flags: u32,
    /// Index within the original waitv array.
    pub entry_idx: u32,
    /// Thread ID.
    pub tid: u64,
    /// Current state.
    pub state: WaiterState,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl WaiterSlot {
    /// Create an inactive slot.
    const fn empty() -> Self {
        Self {
            uaddr: 0,
            expected: 0,
            flags: 0,
            entry_idx: 0,
            tid: 0,
            state: WaiterState::Pending,
            active: false,
        }
    }
}

impl Default for WaiterSlot {
    fn default() -> Self {
        Self::empty()
    }
}

// ---------------------------------------------------------------------------
// WaitQueue — per-call set of queued waiters
// ---------------------------------------------------------------------------

/// Maximum concurrent waiters across all `futex_waitv` calls.
const MAX_WAITERS: usize = 512;

/// Global queue of active `futex_waitv` waiters.
pub struct WaitQueue {
    slots: [WaiterSlot; MAX_WAITERS],
    count: usize,
    /// Total successful wake-ups delivered.
    pub wakeups: u64,
}

impl WaitQueue {
    /// Create an empty wait queue.
    pub const fn new() -> Self {
        Self {
            slots: [const { WaiterSlot::empty() }; MAX_WAITERS],
            count: 0,
            wakeups: 0,
        }
    }

    /// Number of active waiters.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Enqueue a new waiter.  Returns the slot index or `OutOfMemory`.
    fn enqueue(
        &mut self,
        uaddr: u64,
        expected: u64,
        flags: u32,
        entry_idx: u32,
        tid: u64,
    ) -> Result<usize> {
        let idx = self
            .slots
            .iter()
            .position(|s| !s.active)
            .ok_or(Error::OutOfMemory)?;
        self.slots[idx] = WaiterSlot {
            uaddr,
            expected,
            flags,
            entry_idx,
            tid,
            state: WaiterState::Pending,
            active: true,
        };
        self.count += 1;
        Ok(idx)
    }

    /// Remove a waiter by slot index.
    fn dequeue(&mut self, idx: usize) {
        if idx < MAX_WAITERS && self.slots[idx].active {
            self.slots[idx].active = false;
            self.count = self.count.saturating_sub(1);
        }
    }

    /// Wake up to `nr` waiters on `uaddr`.  Returns number woken.
    pub fn wake(&mut self, uaddr: u64, nr: u32) -> u32 {
        let mut woken = 0u32;
        for slot in self.slots.iter_mut() {
            if woken >= nr {
                break;
            }
            if slot.active && slot.uaddr == uaddr && slot.state == WaiterState::Pending {
                slot.state = WaiterState::Woken;
                woken += 1;
            }
        }
        self.wakeups = self.wakeups.saturating_add(woken as u64);
        woken
    }

    /// Scan for a woken waiter for the given `tid`.
    ///
    /// Returns the `entry_idx` of the first woken slot found, or `None`.
    fn find_woken(&self, tid: u64) -> Option<u32> {
        for slot in &self.slots {
            if slot.active && slot.tid == tid && slot.state == WaiterState::Woken {
                return Some(slot.entry_idx);
            }
        }
        None
    }

    /// Remove all waiters for a given `tid`.
    fn drain_tid(&mut self, tid: u64) {
        for slot in self.slots.iter_mut() {
            if slot.active && slot.tid == tid {
                slot.active = false;
                self.count = self.count.saturating_sub(1);
            }
        }
    }
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate a single `FutexWaitvEntry`.
fn validate_entry(e: &FutexWaitvEntry) -> Result<()> {
    if e.uaddr == 0 {
        return Err(Error::InvalidArgument);
    }
    if e.flags & !ENTRY_FLAGS_VALID != 0 {
        return Err(Error::InvalidArgument);
    }
    if e.reserved != 0 {
        return Err(Error::InvalidArgument);
    }
    if !e.is_aligned() {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// sys_futex_waitv — primary handler
// ---------------------------------------------------------------------------

/// `futex_waitv(2)` syscall handler.
///
/// Waits until any entry in `entries` is woken by a matching `futex_wake`,
/// or until `timeout` expires.
///
/// # Arguments
///
/// * `queue`        — Mutable global wait queue.
/// * `entries`      — Slice of futex wait entries (1…`FUTEX_WAITV_MAX`).
/// * `flags`        — Global flags — must be 0.
/// * `timeout`      — Optional absolute deadline.  `None` = wait forever.
/// * `tid`          — Calling thread ID.
/// * `current_vals` — Current values read safely at each entry's `uaddr`.
///                    Must be the same length as `entries`.
///
/// # Returns
///
/// The 0-based index of the entry that woke the thread on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Empty/oversized entry list, non-zero global
///   flags, bad per-entry flags, null or misaligned address, non-zero
///   reserved field, or `current_vals` length mismatch.
/// * [`Error::WouldBlock`]      — Value mismatch detected or timeout expired.
/// * [`Error::OutOfMemory`]     — Wait queue is full.
pub fn sys_futex_waitv(
    queue: &mut WaitQueue,
    entries: &[FutexWaitvEntry],
    flags: u32,
    timeout: Option<WaitvTimeout>,
    tid: u64,
    current_vals: &[u64],
) -> Result<usize> {
    // Global flags — currently reserved; must be zero.
    if flags != 0 {
        return Err(Error::InvalidArgument);
    }

    // Entry count check.
    if entries.is_empty() || entries.len() > FUTEX_WAITV_MAX {
        return Err(Error::InvalidArgument);
    }

    // current_vals must parallel entries.
    if current_vals.len() != entries.len() {
        return Err(Error::InvalidArgument);
    }

    // Timeout already expired?
    if let Some(t) = &timeout {
        if t.is_expired() {
            return Err(Error::WouldBlock);
        }
    }

    // Phase 1: validate all entries; detect any value mismatch atomically.
    for (i, entry) in entries.iter().enumerate() {
        validate_entry(entry)?;
        if current_vals[i] != entry.val {
            return Err(Error::WouldBlock);
        }
    }

    // Phase 2: enqueue one waiter per entry, rolling back on OOM.
    let entry_count = entries.len();
    let mut slot_indices = [0usize; FUTEX_WAITV_MAX];

    for (i, entry) in entries.iter().enumerate() {
        match queue.enqueue(entry.uaddr, entry.val, entry.flags, i as u32, tid) {
            Ok(idx) => slot_indices[i] = idx,
            Err(e) => {
                // Rollback all previously enqueued waiters.
                for j in 0..i {
                    queue.dequeue(slot_indices[j]);
                }
                return Err(e);
            }
        }
    }

    // Phase 3: check for immediate wake (woken during enqueue in a real SMP
    // kernel, or by a prior wake_all on this address in the stub).
    if let Some(idx) = queue.find_woken(tid) {
        queue.drain_tid(tid);
        return Ok(idx as usize);
    }

    // Stub: no real scheduler sleep — return index 0 as the woken entry.
    // In production this is where we schedule out and wait.
    let _ = entry_count;
    Ok(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn q() -> WaitQueue {
        WaitQueue::new()
    }

    #[test]
    fn single_entry_ok() {
        let mut q = q();
        let e = [FutexWaitvEntry::new(
            0x1000,
            42,
            FUTEX_SIZE_U32 | FUTEX_PRIVATE_FLAG,
        )];
        let v = [42u64];
        assert_eq!(sys_futex_waitv(&mut q, &e, 0, None, 1, &v), Ok(0));
    }

    #[test]
    fn empty_entries_rejected() {
        let mut q = q();
        assert_eq!(
            sys_futex_waitv(&mut q, &[], 0, None, 1, &[]),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn nonzero_global_flags_rejected() {
        let mut q = q();
        let e = [FutexWaitvEntry::new(0x1000, 1, FUTEX_SIZE_U32)];
        let v = [1u64];
        assert_eq!(
            sys_futex_waitv(&mut q, &e, 0xFF, None, 1, &v),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn value_mismatch_returns_wouldblock() {
        let mut q = q();
        let e = [FutexWaitvEntry::new(0x2000, 10, FUTEX_SIZE_U32)];
        let v = [99u64]; // mismatch
        assert_eq!(
            sys_futex_waitv(&mut q, &e, 0, None, 1, &v),
            Err(Error::WouldBlock)
        );
    }

    #[test]
    fn expired_timeout_returns_wouldblock() {
        let mut q = q();
        let e = [FutexWaitvEntry::new(0x3000, 5, FUTEX_SIZE_U32)];
        let v = [5u64];
        let t = WaitvTimeout::monotonic(0); // deadline 0 = expired
        assert_eq!(
            sys_futex_waitv(&mut q, &e, 0, Some(t), 1, &v),
            Err(Error::WouldBlock)
        );
    }

    #[test]
    fn null_uaddr_rejected() {
        let mut q = q();
        let e = [FutexWaitvEntry::new(0, 0, FUTEX_SIZE_U32)];
        let v = [0u64];
        assert_eq!(
            sys_futex_waitv(&mut q, &e, 0, None, 1, &v),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn misaligned_uaddr_rejected() {
        let mut q = q();
        // U32 requires 4-byte alignment; 0x1001 is not aligned.
        let e = [FutexWaitvEntry::new(0x1001, 0, FUTEX_SIZE_U32)];
        let v = [0u64];
        assert_eq!(
            sys_futex_waitv(&mut q, &e, 0, None, 1, &v),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn nonzero_reserved_rejected() {
        let mut q = q();
        let mut e = FutexWaitvEntry::new(0x4000, 0, FUTEX_SIZE_U32);
        e.reserved = 1;
        let entries = [e];
        let v = [0u64];
        assert_eq!(
            sys_futex_waitv(&mut q, &entries, 0, None, 1, &v),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn vals_length_mismatch_rejected() {
        let mut q = q();
        let e = [FutexWaitvEntry::new(0x5000, 1, FUTEX_SIZE_U32)];
        let v = [1u64, 2]; // length mismatch
        assert_eq!(
            sys_futex_waitv(&mut q, &e, 0, None, 1, &v),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn multiple_entries_all_enqueued() {
        let mut q = q();
        let entries = [
            FutexWaitvEntry::new(0x1000, 1, FUTEX_SIZE_U32 | FUTEX_PRIVATE_FLAG),
            FutexWaitvEntry::new(0x2000, 2, FUTEX_SIZE_U64),
            FutexWaitvEntry::new(0x3000, 3, FUTEX_SIZE_U32),
        ];
        let v = [1u64, 2, 3];
        assert!(sys_futex_waitv(&mut q, &entries, 0, None, 7, &v).is_ok());
        // At least 3 slots active (may be more from prior tests but we just started).
        assert!(q.count() >= 3);
    }

    #[test]
    fn wake_unblocks_waiter() {
        let mut q = q();
        let e = [FutexWaitvEntry::new(
            0x6000,
            77,
            FUTEX_SIZE_U32 | FUTEX_PRIVATE_FLAG,
        )];
        let v = [77u64];
        sys_futex_waitv(&mut q, &e, 0, None, 99, &v).unwrap();
        let woken = q.wake(0x6000, 1);
        assert_eq!(woken, 1);
        assert_eq!(q.wakeups, 1);
    }

    #[test]
    fn word_bytes_correct() {
        assert_eq!(
            FutexWaitvEntry::new(0x1000, 0, FUTEX_SIZE_U8).word_bytes(),
            1
        );
        assert_eq!(
            FutexWaitvEntry::new(0x1000, 0, FUTEX_SIZE_U16).word_bytes(),
            2
        );
        assert_eq!(
            FutexWaitvEntry::new(0x1000, 0, FUTEX_SIZE_U32).word_bytes(),
            4
        );
        assert_eq!(
            FutexWaitvEntry::new(0x1000, 0, FUTEX_SIZE_U64).word_bytes(),
            8
        );
    }

    #[test]
    fn clock_from_clockid() {
        assert_eq!(FutexClock::from_clockid(0), Ok(FutexClock::Realtime));
        assert_eq!(FutexClock::from_clockid(1), Ok(FutexClock::Monotonic));
        assert_eq!(FutexClock::from_clockid(7), Ok(FutexClock::Boottime));
        assert_eq!(FutexClock::from_clockid(99), Err(Error::InvalidArgument));
    }

    #[test]
    fn unknown_entry_flags_rejected() {
        let mut q = q();
        let e = [FutexWaitvEntry::new(0x1000, 0, 0xFFFF_FF00)];
        let v = [0u64];
        assert_eq!(
            sys_futex_waitv(&mut q, &e, 0, None, 1, &v),
            Err(Error::InvalidArgument)
        );
    }
}
