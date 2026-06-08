// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU affinity management for processes and threads.
//!
//! Implements `sched_setaffinity` / `sched_getaffinity` semantics,
//! allowing processes to be pinned to specific CPUs. The scheduler
//! consults the affinity mask when selecting a CPU for a thread.
//!
//! # Data Structures
//!
//! - [`CpuSet`] — bitmask of allowed CPUs (up to 64)
//! - [`AffinityTable`] — per-PID affinity storage

use oncrix_lib::{Error, Result};

use crate::pid::Pid;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum CPUs supported.
pub const MAX_CPUS: usize = 64;

/// Maximum tracked affinity entries.
const MAX_AFFINITY_ENTRIES: usize = 256;

// ---------------------------------------------------------------------------
// CpuSet
// ---------------------------------------------------------------------------

/// Bitmask representing a set of CPUs.
///
/// Each bit position corresponds to a CPU ID (0..63).
/// A set bit means the CPU is included in the set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct CpuSet(u64);

impl CpuSet {
    /// Empty set (no CPUs).
    pub const EMPTY: Self = Self(0);

    /// All CPUs set.
    pub const ALL: Self = Self(u64::MAX);

    /// Create a set with a single CPU.
    pub const fn single(cpu: usize) -> Self {
        if cpu < MAX_CPUS {
            Self(1u64 << cpu)
        } else {
            Self(0)
        }
    }

    /// Create from raw bitmask.
    ///
    /// # Security
    ///
    /// This constructor is **unchecked**: it stores the raw 64-bit mask
    /// verbatim, including bits for offline or out-of-range CPUs. It
    /// bypasses the bounded constructors ([`single`](Self::single),
    /// [`set`](Self::set), [`from_range`](Self::from_range)) which all clamp
    /// to [`MAX_CPUS`]. A user-supplied mask MUST instead be funnelled
    /// through [`from_bits_checked`](Self::from_bits_checked) so a bit for a
    /// CPU that is not online cannot be persisted into the affinity table
    /// and later steer scheduling onto a non-existent CPU.
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    /// Create from a raw bitmask, masking off any CPU bit at or above
    /// `online`.
    ///
    /// `online` is the count of online CPUs (capped at [`MAX_CPUS`]). Every
    /// bit `>= online` is cleared before the value is stored, so an
    /// attacker-supplied mask can never reference an offline or
    /// out-of-range CPU. The result is empty if no in-range bit was set;
    /// callers that require a non-empty set (e.g. `sched_setaffinity`)
    /// detect this via the downstream [`AffinityTable::set_affinity`]
    /// empty-set rejection.
    ///
    /// # Security
    ///
    /// This is the bounded counterpart to [`from_bits`](Self::from_bits) and
    /// is the only constructor that should be applied to an
    /// untrusted/user-supplied raw mask.
    pub const fn from_bits_checked(bits: u64, online: usize) -> Self {
        // Build a low-`online`-bits mask, saturating at the full 64-bit
        // width when `online >= MAX_CPUS` to avoid a shift overflow.
        let valid = if online >= MAX_CPUS {
            u64::MAX
        } else {
            // online < MAX_CPUS (<= 64) ⇒ 1u64 << online is well-defined.
            (1u64 << online) - 1
        };
        Self(bits & valid)
    }

    /// Return raw bitmask.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Add a CPU to the set.
    pub fn set(&mut self, cpu: usize) {
        if cpu < MAX_CPUS {
            self.0 |= 1u64 << cpu;
        }
    }

    /// Remove a CPU from the set.
    pub fn clear(&mut self, cpu: usize) {
        if cpu < MAX_CPUS {
            self.0 &= !(1u64 << cpu);
        }
    }

    /// Check if a CPU is in the set.
    pub const fn contains(self, cpu: usize) -> bool {
        if cpu < MAX_CPUS {
            (self.0 >> cpu) & 1 != 0
        } else {
            false
        }
    }

    /// Returns the number of CPUs in the set.
    pub const fn count(self) -> u32 {
        self.0.count_ones()
    }

    /// Returns `true` if the set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Compute the intersection of two sets.
    pub const fn and(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Compute the union of two sets.
    pub const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns the lowest-numbered CPU in the set, or `None`.
    pub const fn first(self) -> Option<usize> {
        if self.0 == 0 {
            None
        } else {
            Some(self.0.trailing_zeros() as usize)
        }
    }

    /// Create a set from a range of CPUs `[start, end)`.
    pub fn from_range(start: usize, end: usize) -> Self {
        let mut bits = 0u64;
        let clamped_end = end.min(MAX_CPUS);
        let mut cpu = start;
        while cpu < clamped_end {
            bits |= 1u64 << cpu;
            cpu += 1;
        }
        Self(bits)
    }

    /// Returns the number of CPUs in the set up to `online`,
    /// representing the effective set given the number of online CPUs.
    pub fn effective_count(self, online: usize) -> u32 {
        let mask = if online >= MAX_CPUS {
            u64::MAX
        } else {
            (1u64 << online) - 1
        };
        (self.0 & mask).count_ones()
    }
}

impl Default for CpuSet {
    fn default() -> Self {
        Self::ALL
    }
}

// ---------------------------------------------------------------------------
// Affinity Entry
// ---------------------------------------------------------------------------

/// Per-process CPU affinity entry.
#[derive(Debug, Clone, Copy)]
struct AffinityEntry {
    /// Process ID.
    pid: Pid,
    /// Allowed CPU set.
    cpuset: CpuSet,
    /// Whether this slot is active.
    active: bool,
}

impl Default for AffinityEntry {
    fn default() -> Self {
        Self {
            pid: Pid::new(0),
            cpuset: CpuSet::ALL,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Affinity Table
// ---------------------------------------------------------------------------

/// Global table of per-process CPU affinity masks.
pub struct AffinityTable {
    /// Affinity entries.
    entries: [AffinityEntry; MAX_AFFINITY_ENTRIES],
    /// Number of active entries.
    count: usize,
}

impl AffinityTable {
    /// Create an empty affinity table.
    pub const fn new() -> Self {
        const EMPTY: AffinityEntry = AffinityEntry {
            pid: Pid::new(0),
            cpuset: CpuSet::ALL,
            active: false,
        };
        Self {
            entries: [EMPTY; MAX_AFFINITY_ENTRIES],
            count: 0,
        }
    }

    /// Set the CPU affinity for a process.
    ///
    /// If the process already has an affinity entry, it is updated.
    /// Otherwise a new entry is created.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpuset` is empty.
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn set_affinity(&mut self, pid: Pid, cpuset: CpuSet) -> Result<()> {
        if cpuset.is_empty() {
            return Err(Error::InvalidArgument);
        }

        // Update existing
        for entry in &mut self.entries {
            if entry.active && entry.pid == pid {
                entry.cpuset = cpuset;
                return Ok(());
            }
        }

        // Insert new
        let idx = self
            .entries
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;
        self.entries[idx] = AffinityEntry {
            pid,
            cpuset,
            active: true,
        };
        self.count += 1;
        Ok(())
    }

    /// Get the CPU affinity for a process.
    ///
    /// Returns [`CpuSet::ALL`] if no affinity has been set (default).
    pub fn get_affinity(&self, pid: Pid) -> CpuSet {
        self.entries
            .iter()
            .find(|e| e.active && e.pid == pid)
            .map(|e| e.cpuset)
            .unwrap_or(CpuSet::ALL)
    }

    /// Remove the affinity entry for a process (reset to default).
    pub fn remove(&mut self, pid: Pid) {
        for entry in &mut self.entries {
            if entry.active && entry.pid == pid {
                entry.active = false;
                self.count = self.count.saturating_sub(1);
                return;
            }
        }
    }

    /// Check if a process is allowed to run on a given CPU.
    pub fn is_allowed(&self, pid: Pid, cpu: usize) -> bool {
        self.get_affinity(pid).contains(cpu)
    }

    /// Select the best CPU for a process from `online_cpus`,
    /// respecting its affinity mask. Returns the lowest available CPU.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if no CPU in the affinity
    /// set is online.
    pub fn select_cpu(&self, pid: Pid, online_cpus: CpuSet) -> Result<usize> {
        let affinity = self.get_affinity(pid);
        let candidates = affinity.and(online_cpus);
        candidates.first().ok_or(Error::InvalidArgument)
    }

    /// Returns the number of active affinity entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no affinity entries are set.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for AffinityTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Syscall Interface
// ---------------------------------------------------------------------------

/// Handle `sched_setaffinity(pid, cpusetsize, mask)`.
///
/// Sets the CPU affinity mask for the specified process.
///
/// # SECURITY INVARIANT (unauthenticated entry point)
///
/// This function performs **no permission check** and **no online-CPU
/// validation**: it pins an arbitrary `pid` to a caller-chosen `cpuset`.
/// On Linux, `sched_setaffinity(2)` on a *foreign* task is privileged —
/// the caller must hold `CAP_SYS_NICE` or have an effective UID equal to
/// the target's real or effective UID; otherwise it is `EPERM`. No
/// per-task credential is threaded into this signature and no out-of-file
/// caller exists, so the gate cannot be applied here without a credential
/// in scope.
///
/// The dispatcher MUST therefore call
/// [`do_sched_setaffinity_checked`] instead, passing the authenticated
/// caller credentials, the resolved target effective UID, and the online-
/// CPU count. This bare wrapper is retained only for the privileged
/// in-kernel self-pin path (caller acting on a task it already owns) and
/// must never be reached directly from an untrusted syscall boundary.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if the mask is empty.
pub fn do_sched_setaffinity(table: &mut AffinityTable, pid: Pid, cpuset: CpuSet) -> Result<()> {
    table.set_affinity(pid, cpuset)
}

/// Handle `sched_setaffinity(pid, cpusetsize, mask)` with full
/// authorization and online-CPU validation. This is the entry point a
/// syscall dispatcher MUST use for any request crossing an untrusted
/// boundary.
///
/// `caller` is the authenticated calling process's credentials.
/// `cap_sys_nice` is `true` if the caller holds `CAP_SYS_NICE` in its
/// effective set (the capability is resolved by the dispatcher, which owns
/// the capability subsystem). `target_euid` is the effective UID of the
/// process identified by `pid`. `mask_bits` is the raw, untrusted CPU
/// bitmask supplied by user space and `online` is the current online-CPU
/// count.
///
/// # Security
///
/// * **Authorization (fail-closed).** The pin is permitted only when the
///   caller is privileged (`CAP_SYS_NICE` or effective UID 0) **or** the
///   caller's effective UID equals the target's effective UID. Any other
///   case is denied with [`Error::PermissionDenied`] before the table is
///   touched, so an unprivileged process can never repin a foreign task.
/// * **Mask validation.** The raw `mask_bits` are funnelled through
///   [`CpuSet::from_bits_checked`] so bits for offline/out-of-range CPUs
///   are dropped and can never be persisted.
///
/// # Errors
///
/// - [`Error::PermissionDenied`] if the caller may not pin `pid`
/// - [`Error::InvalidArgument`] if the validated mask is empty (no online
///   CPU selected) or the table cannot accept the entry
pub fn do_sched_setaffinity_checked(
    table: &mut AffinityTable,
    caller: &crate::cred::Credentials,
    cap_sys_nice: bool,
    pid: Pid,
    target_euid: crate::cred::Uid,
    mask_bits: u64,
    online: usize,
) -> Result<()> {
    // SECURITY: gate before any state mutation. Privileged (CAP_SYS_NICE or
    // euid 0) or same-effective-UID callers only; everything else is denied.
    let privileged = cap_sys_nice || caller.is_root();
    if !privileged && caller.euid() != target_euid {
        return Err(Error::PermissionDenied);
    }

    // SECURITY: clamp the untrusted mask to online CPUs before storing so an
    // offline/out-of-range CPU bit cannot enter the affinity table. An empty
    // result is rejected by `set_affinity` as `InvalidArgument`.
    let cpuset = CpuSet::from_bits_checked(mask_bits, online);
    table.set_affinity(pid, cpuset)
}

/// Handle `sched_getaffinity(pid, cpusetsize, mask)`.
///
/// Returns the current CPU affinity mask for the process.
pub fn do_sched_getaffinity(table: &AffinityTable, pid: Pid) -> CpuSet {
    table.get_affinity(pid)
}
