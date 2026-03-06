// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `sched_getaffinity(2)` and `sched_setaffinity(2)` — CPU affinity.
//!
//! CPU affinity specifies the set of CPUs on which a thread is eligible
//! to run.  These syscalls read and write the CPU affinity mask for any
//! thread identified by PID (or the calling thread if PID is 0).
//!
//! # Prototypes
//!
//! ```text
//! int sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask);
//! int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
//! ```
//!
//! # CPU set representation
//!
//! `cpu_set_t` is a bitmask where bit `n` corresponds to CPU `n`.
//! This implementation uses a [`CpuSet`] type backed by an array of
//! `u64` words, supporting up to 4096 CPUs.
//!
//! # Permissions
//!
//! - `sched_setaffinity` on another thread requires that the caller's
//!   effective UID matches the target's, or the caller holds
//!   `CAP_SYS_NICE`.
//! - `sched_getaffinity` can read any thread's affinity.
//!
//! # POSIX
//!
//! `sched_setaffinity`/`sched_getaffinity` are Linux extensions; not
//! POSIX.  The POSIX `pthread_setaffinity_np(3)` wrapper delegates to
//! these syscalls.
//!
//! # References
//!
//! - Linux: `kernel/sched/core.c` (`sched_setaffinity`, `sched_getaffinity`)
//! - `cpu_set_t`: `<sched.h>`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of CPUs supported by the affinity mask.
pub const CPU_SETSIZE: usize = 4096;

/// Number of `u64` words needed to represent `CPU_SETSIZE` bits.
pub const CPU_SET_WORDS: usize = CPU_SETSIZE / 64;

/// Bits per word in a CPU set.
const BITS_PER_WORD: usize = 64;

/// Maximum number of threads in the affinity table.
const MAX_THREADS: usize = 512;

// ---------------------------------------------------------------------------
// CpuSet
// ---------------------------------------------------------------------------

/// A bitmask representing a set of CPUs.
///
/// Bit `n` is set if CPU `n` is in the set.  Backed by `CPU_SET_WORDS`
/// 64-bit words for efficient word-at-a-time operations.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CpuSet {
    /// Raw bitmask words, little-endian bit numbering.
    pub bits: [u64; CPU_SET_WORDS],
}

impl core::fmt::Debug for CpuSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CpuSet({} CPUs set)", self.count())
    }
}

impl Default for CpuSet {
    fn default() -> Self {
        Self::empty()
    }
}

impl CpuSet {
    /// Create an empty (all-zero) CPU set.
    pub const fn empty() -> Self {
        Self {
            bits: [0u64; CPU_SET_WORDS],
        }
    }

    /// Create a CPU set with all `ncpus` CPUs set.
    ///
    /// `ncpus` is clamped to `CPU_SETSIZE`.
    pub fn full(ncpus: usize) -> Self {
        let ncpus = ncpus.min(CPU_SETSIZE);
        let mut set = Self::empty();
        for cpu in 0..ncpus {
            set.set(cpu);
        }
        set
    }

    /// Set CPU `cpu` in the mask.
    ///
    /// No-op if `cpu >= CPU_SETSIZE`.
    pub fn set(&mut self, cpu: usize) {
        if cpu < CPU_SETSIZE {
            self.bits[cpu / BITS_PER_WORD] |= 1u64 << (cpu % BITS_PER_WORD);
        }
    }

    /// Clear CPU `cpu` from the mask.
    ///
    /// No-op if `cpu >= CPU_SETSIZE`.
    pub fn clear(&mut self, cpu: usize) {
        if cpu < CPU_SETSIZE {
            self.bits[cpu / BITS_PER_WORD] &= !(1u64 << (cpu % BITS_PER_WORD));
        }
    }

    /// Test whether CPU `cpu` is set.
    pub const fn is_set(&self, cpu: usize) -> bool {
        if cpu >= CPU_SETSIZE {
            return false;
        }
        (self.bits[cpu / BITS_PER_WORD] >> (cpu % BITS_PER_WORD)) & 1 != 0
    }

    /// Count the number of CPUs in the set.
    pub fn count(&self) -> usize {
        self.bits.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Returns `true` if the set is empty (no CPUs set).
    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|&w| w == 0)
    }

    /// Returns the index of the first set CPU, or `None`.
    pub fn first(&self) -> Option<usize> {
        for (i, &w) in self.bits.iter().enumerate() {
            if w != 0 {
                return Some(i * BITS_PER_WORD + w.trailing_zeros() as usize);
            }
        }
        None
    }

    /// Compute the intersection of two CPU sets.
    pub fn intersection(&self, other: &CpuSet) -> CpuSet {
        let mut result = CpuSet::empty();
        for i in 0..CPU_SET_WORDS {
            result.bits[i] = self.bits[i] & other.bits[i];
        }
        result
    }

    /// Compute the union of two CPU sets.
    pub fn union(&self, other: &CpuSet) -> CpuSet {
        let mut result = CpuSet::empty();
        for i in 0..CPU_SET_WORDS {
            result.bits[i] = self.bits[i] | other.bits[i];
        }
        result
    }

    /// Returns `true` if `self` is a subset of `other`.
    pub fn is_subset_of(&self, other: &CpuSet) -> bool {
        self.bits
            .iter()
            .zip(other.bits.iter())
            .all(|(a, b)| a & b == *a)
    }

    /// Validate that the set is non-empty and all bits fall within the
    /// online CPU range `[0, ncpus)`.
    ///
    /// Returns [`Error::InvalidArgument`] if the set is empty or contains
    /// an offline CPU.
    pub fn validate(&self, ncpus: usize) -> Result<()> {
        if self.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let ncpus = ncpus.min(CPU_SETSIZE);
        // Check that no bits are set beyond the online CPU count.
        for cpu in ncpus..CPU_SETSIZE {
            if self.is_set(cpu) {
                return Err(Error::InvalidArgument);
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Thread affinity entry
// ---------------------------------------------------------------------------

/// Affinity record for one thread.
#[derive(Debug, Clone, Copy)]
pub struct ThreadAffinity {
    /// Thread ID (TID).
    pub tid: u32,
    /// Process ID (for permission checks).
    pub pid: u32,
    /// Owner's effective UID.
    pub euid: u32,
    /// Allowed CPU set.
    pub affinity: CpuSet,
}

impl ThreadAffinity {
    /// Create a new thread affinity record.
    pub fn new(tid: u32, pid: u32, euid: u32, ncpus: usize) -> Self {
        Self {
            tid,
            pid,
            euid,
            affinity: CpuSet::full(ncpus),
        }
    }
}

// ---------------------------------------------------------------------------
// Affinity table
// ---------------------------------------------------------------------------

/// System-wide CPU affinity table.
///
/// Stores per-thread affinity masks indexed by TID.
pub struct AffinityTable {
    /// Fixed-size list of thread entries.
    entries: [Option<ThreadAffinity>; MAX_THREADS],
    /// Number of online CPUs (used for validation).
    pub ncpus: usize,
}

impl AffinityTable {
    /// Create an empty table with `ncpus` online CPUs.
    pub const fn new(ncpus: usize) -> Self {
        Self {
            entries: [const { None }; MAX_THREADS],
            ncpus,
        }
    }

    /// Register a new thread with default (all-CPU) affinity.
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn register_thread(&mut self, tid: u32, pid: u32, euid: u32) -> Result<()> {
        if self.find_slot(tid).is_some() {
            return Ok(()); // already registered
        }
        let slot = self.free_slot().ok_or(Error::OutOfMemory)?;
        self.entries[slot] = Some(ThreadAffinity::new(tid, pid, euid, self.ncpus));
        Ok(())
    }

    /// Remove a thread from the table.
    pub fn unregister_thread(&mut self, tid: u32) {
        for slot in &mut self.entries {
            if slot.map_or(false, |e| e.tid == tid) {
                *slot = None;
                return;
            }
        }
    }

    fn find_slot(&self, tid: u32) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.map_or(false, |e| e.tid == tid))
    }

    fn free_slot(&self) -> Option<usize> {
        self.entries.iter().position(|e| e.is_none())
    }

    /// Get the affinity mask for `tid` (immutable).
    pub fn get(&self, tid: u32) -> Option<&ThreadAffinity> {
        self.entries.iter().flatten().find(|e| e.tid == tid)
    }

    /// Get the affinity mask for `tid` (mutable).
    pub fn get_mut(&mut self, tid: u32) -> Option<&mut ThreadAffinity> {
        self.entries.iter_mut().flatten().find(|e| e.tid == tid)
    }
}

impl Default for AffinityTable {
    fn default() -> Self {
        Self::new(1)
    }
}

// ---------------------------------------------------------------------------
// Permission check
// ---------------------------------------------------------------------------

/// Check that `caller` may set the affinity of `target`.
///
/// The caller must either:
/// - Be the same thread (same TID), or
/// - Share the same process (same PID), or
/// - Have matching effective UIDs, or
/// - Hold `CAP_SYS_NICE`.
///
/// Returns [`Error::PermissionDenied`] on failure.
fn check_set_permission(
    caller_tid: u32,
    caller_pid: u32,
    caller_euid: u32,
    cap_sys_nice: bool,
    target: &ThreadAffinity,
) -> Result<()> {
    if caller_tid == target.tid {
        return Ok(());
    }
    if caller_pid == target.pid {
        return Ok(());
    }
    if caller_euid == target.euid {
        return Ok(());
    }
    if cap_sys_nice {
        return Ok(());
    }
    Err(Error::PermissionDenied)
}

// ---------------------------------------------------------------------------
// Syscall handlers
// ---------------------------------------------------------------------------

/// `sched_setaffinity(2)` — set the CPU affinity of thread `tid`.
///
/// # Arguments
///
/// - `table` — Mutable affinity table.
/// - `target_tid` — Thread to modify.  0 means the caller's thread.
/// - `caller_tid` — TID of the calling thread.
/// - `caller_pid` — PID of the calling process.
/// - `caller_euid` — Effective UID of the caller.
/// - `cap_sys_nice` — Whether the caller holds `CAP_SYS_NICE`.
/// - `mask` — Desired CPU affinity mask.
///
/// # Errors
///
/// - [`Error::NotFound`] — `target_tid` is not in the table.
/// - [`Error::PermissionDenied`] — Caller cannot modify target's affinity.
/// - [`Error::InvalidArgument`] — `mask` is empty or contains offline CPUs.
pub fn sys_sched_setaffinity(
    table: &mut AffinityTable,
    target_tid: u32,
    caller_tid: u32,
    caller_pid: u32,
    caller_euid: u32,
    cap_sys_nice: bool,
    mask: CpuSet,
) -> Result<()> {
    let tid = if target_tid == 0 {
        caller_tid
    } else {
        target_tid
    };

    mask.validate(table.ncpus)?;

    let target = table.get(tid).ok_or(Error::NotFound)?;
    check_set_permission(caller_tid, caller_pid, caller_euid, cap_sys_nice, target)?;

    let entry = table.get_mut(tid).ok_or(Error::NotFound)?;
    entry.affinity = mask;
    Ok(())
}

/// `sched_getaffinity(2)` — read the CPU affinity of thread `tid`.
///
/// # Arguments
///
/// - `table` — Affinity table.
/// - `target_tid` — Thread to query.  0 means the caller's thread.
/// - `caller_tid` — TID of the calling thread.
///
/// # Returns
///
/// A copy of the target thread's [`CpuSet`].
///
/// # Errors
///
/// - [`Error::NotFound`] — `target_tid` is not registered.
pub fn sys_sched_getaffinity(
    table: &AffinityTable,
    target_tid: u32,
    caller_tid: u32,
) -> Result<CpuSet> {
    let tid = if target_tid == 0 {
        caller_tid
    } else {
        target_tid
    };
    let entry = table.get(tid).ok_or(Error::NotFound)?;
    Ok(entry.affinity)
}

/// Return the number of CPUs online according to the affinity table.
pub const fn sys_cpu_count(table: &AffinityTable) -> usize {
    table.ncpus
}

/// Return the size in bytes needed for a `cpu_set_t` covering `ncpus` CPUs.
///
/// Rounds up to the nearest 8-byte (u64) boundary.
pub const fn cpu_set_size_bytes(ncpus: usize) -> usize {
    let words = (ncpus + 63) / 64;
    words * 8
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_table(ncpus: usize) -> AffinityTable {
        let mut t = AffinityTable::new(ncpus);
        t.register_thread(1, 1, 0).unwrap();
        t.register_thread(2, 1, 0).unwrap();
        t.register_thread(3, 2, 500).unwrap();
        t
    }

    #[test]
    fn test_getaffinity_default() {
        let table = make_table(4);
        let set = sys_sched_getaffinity(&table, 1, 1).unwrap();
        assert!(set.is_set(0));
        assert!(set.is_set(3));
        assert!(!set.is_set(4));
    }

    #[test]
    fn test_setaffinity_self() {
        let mut table = make_table(8);
        let mut mask = CpuSet::empty();
        mask.set(0);
        mask.set(2);
        sys_sched_setaffinity(&mut table, 0, 1, 1, 0, false, mask).unwrap();
        let set = sys_sched_getaffinity(&table, 1, 1).unwrap();
        assert!(set.is_set(0));
        assert!(set.is_set(2));
        assert!(!set.is_set(1));
    }

    #[test]
    fn test_setaffinity_other_same_pid() {
        let mut table = make_table(4);
        let mut mask = CpuSet::empty();
        mask.set(1);
        // Thread 1 and 2 share PID 1 → allowed
        sys_sched_setaffinity(&mut table, 2, 1, 1, 0, false, mask).unwrap();
    }

    #[test]
    fn test_setaffinity_other_denied() {
        let mut table = make_table(4);
        let mut mask = CpuSet::empty();
        mask.set(0);
        // Thread 1 (pid=1, euid=0) trying to set thread 3 (pid=2, euid=500)
        let result = sys_sched_setaffinity(&mut table, 3, 1, 1, 0, false, mask);
        assert!(matches!(result, Err(Error::PermissionDenied)));
    }

    #[test]
    fn test_setaffinity_with_cap() {
        let mut table = make_table(4);
        let mut mask = CpuSet::empty();
        mask.set(0);
        sys_sched_setaffinity(&mut table, 3, 1, 1, 0, true, mask).unwrap();
    }

    #[test]
    fn test_empty_mask_rejected() {
        let mut table = make_table(4);
        let mask = CpuSet::empty();
        let result = sys_sched_setaffinity(&mut table, 1, 1, 1, 0, false, mask);
        assert!(result.is_err());
    }

    #[test]
    fn test_offline_cpu_rejected() {
        let mut table = make_table(2); // only CPUs 0 and 1 online
        let mut mask = CpuSet::empty();
        mask.set(3); // CPU 3 is offline
        let result = sys_sched_setaffinity(&mut table, 1, 1, 1, 0, false, mask);
        assert!(result.is_err());
    }

    #[test]
    fn test_cpu_set_operations() {
        let mut a = CpuSet::empty();
        a.set(0);
        a.set(2);
        let mut b = CpuSet::empty();
        b.set(1);
        b.set(2);
        let inter = a.intersection(&b);
        assert!(inter.is_set(2));
        assert!(!inter.is_set(0));
        assert!(!inter.is_set(1));
        let uni = a.union(&b);
        assert!(uni.is_set(0));
        assert!(uni.is_set(1));
        assert!(uni.is_set(2));
    }
}
